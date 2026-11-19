"""Controller regressions with a deterministic Drive CAS double."""

from copy import deepcopy
from hashlib import sha256
import http.client
import json
import socket
import subprocess
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from epub_triage.backend import Backend
from epub_triage.colab_cli import Dispatcher, agy_response
from epub_triage.colab_controller import Controller
from epub_triage.colab_drive import (CandidateStore, Conflict, DriveError, EvidenceStore, FOLDER, Journal, Quarantine, Scope,
                                    SHORTCUT, candidate_template, canonical, evidence_template, identity, journal_template, stamp)
from epub_triage.colab_gemini import messages_only, wire
from epub_triage.colab_runtime import LEASE, Runtime, WorkerPending, reap_abandoned
from epub_triage.colab_worker import MiB, inspect, limits_for, static_reply
from epub_triage.review_cli import ReviewerUnavailable


SCOPE = Scope("intake", "quarantine", "repair", "editions", "reports", "evidence")


class MemoryDrive:
    def __init__(self):
        self.files = {}
        self.bytes = {}
        self.lost = None
        self.delayed = None
        for folder in vars(SCOPE).values():
            self.add(folder, mime=FOLDER)
        self.files["intake"]["properties"] = {"epubValidatorV5Journal": "journal"}
        self.add("journal", "reports", canonical(journal_template("intake", "account")), "application/json")
        self.add("probe", "reports", canonical({"purpose": "epub-v5-disposable-cas-probe"}), "application/json")
        self.add("moveA", "reports", mime=FOLDER)
        self.add("moveB", "reports", mime=FOLDER)
        self.add("mover", "moveA", b"harmless control")
        for item in ("moveA", "moveB", "mover"):
            self.files[item]["properties"] = {"epubValidatorV5Probe": "disposable"}
        self.add("book", "intake", b"benign bytes", name="same.epub")

    def add(self, item, parent=None, data=b"", mime="application/epub+zip", name=None):
        self.files[item] = {"id": item, "mimeType": mime, "name": name or item, "properties": {},
                            "parents": [parent] if parent else [], "headRevisionId": "1", "version": "1",
                            "size": str(len(data)), "sha256Checksum": sha256(data).hexdigest(),
                            "capabilities": {"canEdit": True, "canDownload": True, "canAddChildren": True,
                                             "canMoveItemWithinDrive": True}}
        self.bytes[item] = data

    def meta(self, item):
        if item not in self.files:
            raise DriveError("Inaccessible.")
        return deepcopy(self.files[item])

    def tagged_meta(self, item):
        return self.meta(item), self.etag(item)

    def etag(self, item):
        return '"' + self.files[item]["version"] + '"'

    def children(self, folder):
        for value in self.files.values():
            if folder["id"] in value["parents"]:
                yield deepcopy(value)

    def read(self, item, allowance, sink, expected=None):
        data = self.bytes[item]
        if len(data) > allowance or expected and identity(self.meta(item)) != expected:
            raise Conflict("Changed.")
        sink.write(data)
        return self.etag(item)

    def patch_journal(self, item, data, tag):
        self.check(item, tag)
        meta = self.files[item]
        meta.update(size=str(len(data)), sha256Checksum=sha256(data).hexdigest(),
                    headRevisionId=meta["version"])
        self.bytes[item] = data

    def patch_media(self, item, data, tag, content_type):
        if item == "candidate" and self.lost == "before":
            self.delayed = item, data, tag, content_type
            self.lost = None
            raise DriveError("Upload was interrupted before mutation.")
        self.patch_journal(item, data, tag)
        if item == "candidate" and self.lost == "after":
            self.lost = None
            raise DriveError("Upload was interrupted after mutation.")

    def check(self, item, tag):
        if self.etag(item) != tag:
            raise Conflict("Stale physical request.")
        self.files[item]["version"] = str(int(self.files[item]["version"]) + 1)

    def patch_metadata(self, item, tag, data, *, add=None, remove=None):
        if item == "book" and add and self.lost == "before":
            self.delayed = (item, tag, data, add, remove)
            self.lost = None
            raise DriveError("Lost response before mutation.")
        self.check(item, tag)
        meta = self.files[item]
        if add:
            meta["parents"] = [add]
        if data.get("properties"):
            meta["properties"].update(data["properties"])
        if item == "book" and add and self.lost == "after":
            self.lost = None
            raise DriveError("Lost response after mutation.")
        return deepcopy(meta)

    def release_delayed(self):
        item, tag, data, add, remove = self.delayed
        self.patch_metadata(item, tag, data, add=add, remove=remove)


class SimRuntime:
    def configuration(self):
        return {"engine": "test-double"}

    def inspect(self, drive, scope, source, **kwargs):
        return {"sha256": source["sha256"], "action": "leave", "status": "clean"}


class DriveCoordinationTests(unittest.TestCase):
    def setUp(self):
        self.drive = MemoryDrive()
        self.journal = Journal(self.drive, SCOPE, "journal", "account")
        self.journal.qualify("probe")

    def test_scope_and_shortcut_resolution(self):
        self.drive.add("nested", "intake", mime=FOLDER)
        self.drive.add("second", "nested", name="same.epub")
        self.drive.add("outside", name="same.epub")
        self.drive.add("shortcut", "nested", mime=SHORTCUT)
        self.drive.files["shortcut"]["shortcutDetails"] = {"targetId": "outside"}
        self.drive.files["repair"]["parents"] = ["intake"]
        self.drive.add("generated", "repair", name="generated.epub")
        selection, denied = SCOPE.select(self.drive, ("intake", "outside", "generated"))
        self.assertEqual([item["id"] for item in selection], ["book", "second"])
        self.assertEqual(set(denied), {"outside", "shortcut", "generated"})
        selection, _ = SCOPE.select(self.drive, recursive=False)
        self.assertEqual([item["id"] for item in selection], ["book"])

    def test_single_journal_and_old_owner_cannot_commit(self):
        self.drive.add("other", "reports", canonical(journal_template("intake", "account")), "application/json")
        with self.assertRaises(DriveError):
            Journal(self.drive, SCOPE, "other", "account").snapshot()
        generation = self.journal.acquire("original")
        old, old_tag, _ = self.journal.snapshot()
        with self.assertRaises(Conflict):
            self.journal.acquire("newer")
        self.journal.acquire("newer", takeover=True)
        with self.assertRaises(Conflict):
            self.journal.commit("original", generation, "settings", {})
        with self.assertRaises(Conflict):
            self.drive.patch_journal("journal", canonical(old), old_tag)

    def prepare_move(self):
        quarantine = Quarantine(self.drive, SCOPE, self.journal)
        quarantine.qualify("mover", "moveA", "moveB")
        generation = self.journal.acquire("original")
        book = {"source": identity(self.drive.meta("book")), "state": "pending", "configuration": "same",
                "operation": {"id": "intent", "action": "quarantine", "status": "pending"}}
        self.journal.commit("original", generation, "same", {"book": book})
        return quarantine, generation, book

    def test_acknowledgement_lost_after_move(self):
        quarantine, generation, book = self.prepare_move()
        self.drive.lost = "after"
        with self.assertRaises(DriveError):
            quarantine.dispatch("original", generation, book)
        quarantine.recover("original", generation)
        quarantine.recover("original", generation)
        value, _, _ = self.journal.snapshot()
        self.assertEqual(value["books"]["book"]["state"], "complete")
        self.assertIsNone(value["in_flight_physical"])

    def test_same_writer_resumes_exact_pending_move(self):
        quarantine, generation, book = self.prepare_move()
        self.drive.lost = "before"
        with self.assertRaises(DriveError):
            quarantine.dispatch("original", generation, book)
        quarantine.recover("original", generation)
        self.assertEqual(self.drive.meta("book")["parents"], ["quarantine"])
        with self.assertRaises(Conflict):
            self.drive.release_delayed()

    def test_takeover_drains_pending_physical_request(self):
        quarantine, generation, book = self.prepare_move()
        self.drive.lost = "before"
        with self.assertRaises(DriveError):
            quarantine.dispatch("original", generation, book)
        with self.assertRaises(Conflict):
            self.journal.acquire("newer", takeover=True)
        quarantine.recover("newer", None, takeover=True)
        next_generation = self.journal.acquire("newer", takeover=True)
        with self.assertRaises(Conflict):
            self.drive.release_delayed()
        state, _, _ = self.journal.snapshot()
        rebound = state["books"]["book"]
        self.assertEqual(book["source"]["sha256"], rebound["source"]["sha256"])
        self.assertNotEqual(book["source"]["version"], rebound["source"]["version"])
        quarantine.dispatch("newer", next_generation, rebound)
        self.assertEqual(self.drive.meta("book")["parents"], ["quarantine"])

    def test_resume_rechecks_clean_file_without_mutation(self):
        controller = Controller(self.drive, SCOPE, SimRuntime(), journal=self.journal, report_only=False)
        controller.acquire()
        controller.select()
        controller.run()
        self.assertEqual(controller.entries["book"]["state"], "evaluated")
        self.drive.patch_metadata("book", self.drive.etag("book"), {"properties": {"test": "changed"}})
        controller.run(resume=True)
        self.assertEqual(controller.entries["book"]["state"], "stale")

    def test_report_only_never_commits(self):
        controller = Controller(self.drive, SCOPE, SimRuntime(), journal=self.journal)
        original = self.journal.snapshot()
        controller.select()
        controller.run()
        self.assertEqual(self.journal.snapshot(), original)

    def test_preflight_cap_and_static_only_hold(self):
        with self.assertRaises(ValueError):
            limits_for(128 * MiB, 280 * MiB)
        _, scratch = limits_for(20 * MiB, 320 * MiB)
        self.assertEqual(scratch, (320 - 20 - 200 - 16) * MiB)
        with tempfile.TemporaryDirectory() as directory, patch("epub_triage.colab_worker.Backend") as backend:
            path = Path(directory) / "book.epub"
            path.write_bytes(b"benign bytes")
            request = {"sha256": sha256(b"benign bytes").hexdigest(), "stage_bytes": 320 * MiB,
                       "behavior": False}
            backend.return_value.preflight.return_value = {"daily_published_epoch": 1}
            backend.return_value.inspect.return_value = {
                "security": {"complete": True, "findings": []}, "quality": {"complete": True, "findings": []}}
            clean = inspect({}, path, path.parent, request)
            self.assertEqual(clean["status"], "behavior_pending")
            self.assertEqual(clean["action"], "hold")
            self.assertEqual(clean["static_action"], "leave")
            backend.return_value.inspect.return_value = {
                "security": {"complete": True, "findings": [{"kind": "malware", "code": "test",
                                                            "detail": "harmless simulated finding"}]},
                "quality": {"complete": False, "findings": []}}
            self.assertEqual(inspect({}, path, path.parent, request)["action"], "quarantine")

    def test_identical_evidence_has_distinct_book_and_expiry_slots(self):
        self.drive.files["evidence"]["properties"] = {"epubValidatorV5Evidence": "traces"}
        self.drive.add("traces", "evidence", canonical(evidence_template("intake")), "application/json")
        self.drive.add("another", "intake", b"benign bytes", name="another.epub")
        evidence = EvidenceStore(self.drive, SCOPE, self.journal, "traces")
        details = [{"test": "identical harmless trace"}]
        records = {item: {"source": identity(self.drive.meta(item)), "configuration": "cfg",
                          "trace": {"sha256": stamp(details), "slot": item + "-slot",
                                    "expires_at": expiration, "status": "evidence folder upload pending"}}
                   for item, expiration in (("book", 1), ("another", 9999999))}
        generation = self.journal.acquire("notebook")
        self.journal.commit("notebook", generation, "cfg", records)
        for book in records.values():
            evidence.write("notebook", generation, book, details)
        state, _, _ = self.journal.snapshot()
        current = state["books"]["book"]
        trace = current.pop("trace")
        current["history"] = [{"trace": trace}]
        evidence.expire("notebook", generation, current, trace["slot"])
        saved = evidence.snapshot()[0]["traces"]
        self.assertEqual(set(saved), {"another-slot"})
        self.assertEqual(saved["another-slot"]["sha256"], stamp(details))
        self.assertEqual(self.journal.snapshot()[0]["books"]["book"]["history"][0]["trace"]["status"], "expired")

    def test_candidate_upload_recovery_fences_delayed_request(self):
        self.drive.add("binaryprobe", "evidence", canonical(candidate_template("disposable")),
                       "application/octet-stream")
        self.drive.files["binaryprobe"]["properties"] = {"epubValidatorV5Candidate": "disposable"}
        self.drive.add("candidate", "evidence", canonical(candidate_template("book")),
                       "application/octet-stream")
        self.drive.files["candidate"]["properties"] = {"epubValidatorV5Candidate": "book"}
        probe = CandidateStore(self.drive, SCOPE, self.journal, "binaryprobe")
        permitted = {probe.qualify()}
        store = CandidateStore(self.drive, SCOPE, self.journal, "candidate", permitted)
        record = {"source": identity(self.drive.meta("book")), "configuration": "cfg"}
        generation = self.journal.acquire("writer")
        self.journal.commit("writer", generation, "cfg", {"book": record})
        original = b"harmless staged candidate bytes"
        expected = sha256(original).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.epub"
            path.write_bytes(original)
            self.drive.lost = "before"
            with self.assertRaises(DriveError):
                store.store("writer", generation, record, path, expected)
            store.recover("new", None, takeover=True)
            with self.assertRaises(Conflict):
                self.drive.patch_media(*self.drive.delayed)
            self.assertEqual(self.journal.snapshot()[0]["books"]["book"]["candidate"]["status"],
                             "staging_needs_retry")
            next_generation = self.journal.acquire("new", takeover=True)
            self.drive.lost = "after"
            with self.assertRaises(DriveError):
                store.store("new", next_generation, record, path, expected)
            store.recover("new", next_generation)
            renewed = store.store("new", next_generation, record, path, expected)
            self.assertEqual(renewed["candidate"]["sha256"], expected)
            self.assertEqual(self.journal.snapshot()[0]["books"]["book"]["candidate"]["status"], "staged")
            self.assertEqual(self.drive.bytes["candidate"], original)

    def test_abandoned_stage_reaper_preserves_live_and_unrecognized_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = Runtime(database="/tmp", epubcheck_jar="/tmp/none.jar", temp_root=directory)
            interrupted = Runtime(database="/tmp", epubcheck_jar="/tmp/none.jar", temp_root=directory)
            dangling = root / "epub-v5-stage-unrecognized"
            dangling.mkdir()
            (dangling / LEASE).symlink_to(live.root / LEASE)
            marker = interrupted.root / "abandoned.epub"
            marker.write_bytes(b"harmless prior stage")
            interrupted.lease.close()
            try:
                self.assertEqual(reap_abandoned(directory), 1)
                self.assertTrue(live.root.is_dir())
                self.assertTrue(dangling.is_dir())
                self.assertFalse(marker.exists())
                self.assertFalse(interrupted.root.exists())
            finally:
                live.close()

    def test_gemini_probe_wire_accepts_text_and_rejects_non_text(self):
        class LocalConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.connect(str(endpoint))

        with tempfile.TemporaryDirectory() as directory:
            endpoint = Path(directory) / "wire.sock"
            with wire(endpoint, ticket="test-ticket", model="gemini-test", marker="public-control") as (errors, hits):
                headers = {"x-goog-api-key": "test-ticket"}
                route = "/v1beta/models/gemini-test:generateContent"
                connection = LocalConnection("local")
                payload = {"contents": [{"role": "user", "parts": [{"text": "harmless"}]}]}
                registration = {"tools": [{"googleSearch": {}}]}
                with self.assertRaises(ValueError):
                    messages_only({**payload, **registration})
                connection.request("POST", route, json.dumps({**payload, **registration}), headers=headers)
                rejected = connection.getresponse()
                self.assertEqual(rejected.status, 503)
                rejected.read()
                self.assertEqual(hits, [])
                self.assertEqual(errors, [True])
                connection.request("POST", route, json.dumps(payload), headers=headers)
                reply = connection.getresponse()
                self.assertEqual(reply.status, 200)
                self.assertIn(b"public-control", reply.read())
                self.assertEqual(hits, [True])
                self.assertEqual(errors, [True])
                connection.request("POST", "/unqualified", headers=headers)
                reply = connection.getresponse()
                self.assertEqual(reply.status, 403)
                reply.read()
                payload["contents"][0]["parts"] = [{"fileData": {"fileUri": "file:///probe"}}]
                connection.request("POST", route, json.dumps(payload), headers=headers)
                reply = connection.getresponse()
                self.assertEqual(reply.status, 503)
                reply.read()
                connection.close()

    def test_static_timeout_returns_pending_without_worker_diagnostics(self):
        marker = b"disposable sensitive diagnostic"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            backend = Backend({"epubcheck_jar": home / "test.jar"}, home)
            backend.epoch = time.time()
            with patch("epub_triage.backend.bounded_worker", side_effect=subprocess.TimeoutExpired(
                    ["static worker"], 300, stderr=marker)):
                reply = static_reply(backend.inspect_repair, home / "book.epub", {})
            self.assertEqual(reply, {"pending": "static_timeout", "operation": "inspect-repair"})
            self.assertNotIn(marker, canonical(reply))
            runtime = Runtime(database=home, epubcheck_jar=home / "test.jar", temp_root=directory)
            try:
                with runtime.job() as (job, request):
                    with patch("epub_triage.colab_runtime.bounded_worker",
                               return_value=(0, canonical(reply), marker)):
                        with self.assertRaisesRegex(WorkerPending, "timed out during inspect-repair") as error:
                            runtime.launch(job, {**request, "operation": "inspect"})
                        self.assertNotIn(marker.decode(), str(error.exception))
                    with patch("epub_triage.colab_runtime.bounded_worker",
                               return_value=(1, b"", marker)):
                        with self.assertRaisesRegex(WorkerPending, "worker failed") as error:
                            runtime.launch(job, {**request, "operation": "inspect"})
                        self.assertNotIn(marker.decode(), str(error.exception))
            finally:
                runtime.close()

    def test_runtime_closes_after_job_and_reviewer_pending_does_not_load_credentials(self):
        runtime = Runtime(database="/tmp", epubcheck_jar="/tmp/none.jar")
        with runtime.job() as (job, request):
            self.assertTrue(job.is_dir())
            self.assertEqual(set(request["marker_paths"]), {"drive_mount", "credential_cache",
                                                          "unrelated_book", "notebook_channel"})
        self.assertFalse(job.exists())
        runtime.close()
        self.assertFalse(runtime.root.exists())
        dispatcher = Dispatcher(lambda _: self.fail("Unqualified selection fetched credentials"))
        with self.assertRaises(ReviewerUnavailable):
            dispatcher("agy", {}, {})
        dispatcher.binaries["agy"] = (Path("/trusted/agy"), "0" * 64)
        dispatcher.local_routing["agy"] = "gemini-test"
        with self.assertRaisesRegex(ReviewerUnavailable, "native-tool"):
            dispatcher("agy", {"agy_model": "gemini-test"}, {})
        with self.assertRaises(ReviewerUnavailable):
            agy_response('{"status":"INTERRUPTED","structured_output":{}}')


if __name__ == "__main__":
    unittest.main()
