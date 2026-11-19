"""Independent local Drive-service model for the v5 acceptance contract."""
import copy
import hashlib
import io
import json
import re
import threading
import unittest

from epub_triage import colab_drive as cloud


class Reply:
    def __init__(self, status, data=None, media=b"", etag=None):
        self.status_code = status
        self.data = data
        self.media = media
        self.headers = {} if etag is None else {"ETag": etag}

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def json(self):
        return copy.deepcopy(self.data)

    def iter_content(self, chunk_size):
        for offset in range(0, len(self.media), chunk_size):
            yield self.media[offset:offset + chunk_size]


class DriveService:
    """Implements only the requests in these cases. Every side effect is observable."""
    def __init__(self):
        self.objects = {}
        self.lock = threading.RLock()
        self.delay = None
        self.failure = None
        self.physical_failure = None
        self.move_commits = []
        self.honor_match = True
        self.writes = []
        self.media_hook = None

    def add(self, item, parent, mime, data=b"", name=None, **fields):
        meta = dict(id=item, parents=[parent] if parent else [], mimeType=mime, name=name or item,
                    trashed=False, version="1", headRevisionId="rev1", size=str(len(data)),
                    sha256Checksum=hashlib.sha256(data).hexdigest(),
                    capabilities=dict(canDownload=True, canEdit=True, canAddChildren=True))
        meta.update(fields)
        self.objects[item] = [meta, data]
        return meta

    def request(self, method, url, **request):
        params = request.get("params", {})
        item = url.rsplit("/", 1)[-1]
        if (method == "PATCH" and self.delay and self.delay[0] == threading.current_thread().name
                and (len(self.delay) == 3 or item == self.delay[3])):
            self.delay[1].set()
            if not self.delay[2].wait(3):
                raise AssertionError("Test never released the queued request")
        with self.lock:
            if item == "about":
                return Reply(200, {"user": {"permissionId": "user"}})
            if item == "files" and method == "GET":
                parent = re.match("'([^']+)'", params["q"])[1]
                return Reply(200, {"files": [m for m, _ in self.objects.values()
                                             if parent in m["parents"] and not m["trashed"]]})
            if item not in self.objects:
                return Reply(404)
            m, data = self.objects[item]
            etag = '"' + m["version"] + '"'
            if method == "GET":
                if params.get("alt") == "media":
                    if self.media_hook:
                        self.media_hook(m)
                    return Reply(200, media=data, etag=etag)
                return Reply(200, m, etag=etag)
            if method == "PATCH":
                if not m["capabilities"].get("canEdit"):
                    return Reply(403)
                if self.honor_match and request["headers"]["If-Match"] != etag:
                    return Reply(412)
                if self.failure in ("before", ("before", item)):
                    self.failure = None
                    raise OSError("injected connection loss")
                if "json" in request:
                    if self.physical_failure == ("before", item):
                        self.physical_failure = None
                        raise OSError("connection lost before move")
                    m["version"] = str(int(m["version"]) + 1)
                    m.setdefault("properties", {}).update(request["json"].get("properties", {}))
                    if "addParents" in params:
                        if params["removeParents"] not in m["parents"]:
                            return Reply(409)
                        m["parents"] = [params["addParents"]]
                        self.move_commits.append(item)
                    self.writes.append(item)
                    if self.physical_failure == ("after", item):
                        self.physical_failure = None
                        raise OSError("connection lost after move")
                    return Reply(200, m)
                payload = bytes(request["data"])
                revision = int(m["version"]) + 1
                m.update(version=str(revision), headRevisionId=f"rev{revision}", size=str(len(payload)),
                         sha256Checksum=hashlib.sha256(payload).hexdigest())
                self.objects[item][1] = payload
                self.writes.append(item)
                if self.failure in ("after", ("after", item)):
                    self.failure = None
                    raise OSError("injected lost response")
                return Reply(200, {"id": item})
        raise AssertionError((method, item))


class DriveCases(unittest.TestCase):
    def setUp(self):
        self.service = DriveService()
        self.drive = cloud.Drive(self.service)
        self.scope = cloud.Scope("intake", "q", "rep", "out", "reports", "trace")
        add = self.service.add
        for item in ("intake", "q", "rep", "reports", "trace", "outside"):
            add(item, None, cloud.FOLDER)
        add("out", "intake", cloud.FOLDER)
        add("sub", "intake", cloud.FOLDER)
        for item, parent in (("book", "intake"), ("deep", "sub"), ("prior", "out"), ("secret", "outside")):
            add(item, parent, "application/epub+zip", b"benign fixture", item+".epub")
        add("escape", "intake", cloud.SHORTCUT, shortcutDetails={"targetId": "secret"})
        add("inside", "intake", cloud.SHORTCUT, shortcutDetails={"targetId": "deep"})
        self.service.objects["intake"][0]["properties"] = {"epubValidatorV5Journal": "journal"}
        add("journal", "reports", "application/json", cloud.canonical(cloud.journal_template("intake", "user")))
        add("probe", "reports", "application/json", b'{"purpose":"epub-v5-disposable-cas-probe"}')

    def test_folder_and_shortcut_scope(self):
        found, denied = self.scope.select(self.drive)
        self.assertEqual({x["id"] for x in found}, {"deep", "book"})
        self.assertIn("escape", denied)
        found, denied = self.scope.select(self.drive, ("secret", "out", "deep"))
        self.assertEqual([x["id"] for x in found], ["deep"])
        self.assertEqual(set(denied), {"secret", "out"})
        self.service.objects["deep"][0]["capabilities"]["canDownload"] = False
        found, denied = self.scope.select(self.drive, ("deep",))
        self.assertFalse(found)
        self.assertIn("deep", denied)
        self.assertFalse(self.service.writes)

    def test_transfer_bound_and_revision_drift(self):
        original = cloud.identity(self.drive.meta("book"))
        for cap in (0, original["size"] - 1):
            dst = io.BytesIO()
            with self.assertRaises(cloud.DriveError):
                self.drive.read("book", cap, dst, original)
            self.assertEqual(dst.getvalue(), b"")
        self.service.media_hook = lambda m: m.update(version="2")
        with self.assertRaises(cloud.Conflict):
            self.drive.read("book", original["size"], io.BytesIO(), original)

    def test_interrupted_moves_and_uploads_observed_without_replay(self):
        source = cloud.identity(self.drive.meta("book"))
        def record(action, **fields):
            return dict(source=source, operation=dict(action=action, expected_sha256=source["sha256"], **fields))
        move = record("quarantine", dispatched=True)
        self.assertEqual(cloud.reconcile(self.drive, self.scope, move)["operation"]["status"], "pending")
        self.service.objects["book"][0]["parents"] = ["q"]
        for _ in range(2):
            self.assertEqual(cloud.reconcile(self.drive, self.scope, move)["operation"]["status"], "complete")
        self.service.objects["book"][0]["parents"] = ["intake"]
        upload = record("publish", dispatched=True, destination_id="reserved")
        self.assertIn(cloud.reconcile(self.drive, self.scope, upload)["operation"]["status"],
                      ("ambiguous", "stale_or_inaccessible"))
        self.service.add("reserved", "out", "application/epub+zip", b"benign fixture")
        for _ in range(2):
            self.assertEqual(cloud.reconcile(self.drive, self.scope, upload)["operation"]["status"], "complete")
        self.service.objects["reserved"][0]["parents"] = ["outside"]
        self.assertEqual(cloud.reconcile(self.drive, self.scope, upload)["operation"]["status"], "ambiguous")
        self.service.objects["book"][0]["version"] = "2"
        self.assertNotEqual(cloud.reconcile(self.drive, self.scope, move)["operation"]["status"], "complete")
        self.assertEqual(self.service.writes, [])

    def test_two_candidates_for_one_intake_cannot_both_be_canonical(self):
        self.service.add("other", "reports", "application/json",
                         cloud.canonical(cloud.journal_template("intake", "user")))
        with self.assertRaises(cloud.DriveError):
            cloud.Journal(self.drive, self.scope, "other", "user").snapshot()

    def test_notebook_review_and_file_diff_identity_for_three_simulated_reviewers(self):
        from contextlib import contextmanager
        import tempfile
        from pathlib import Path
        from epub_triage.colab_controller import Controller
        from epub_triage.colab_review import Review

        expected = "1" * 64
        class Runtime:
            def configuration(self):
                return {"checked": "fixture"}
            @contextmanager
            def review(self, drive, scope, source, stage_bytes):
                finding = {"occurrence": "word", "start": 0, "end": 4, "locator": None,
                           "finding": {"member": "one.xhtml", "code": "fixture-warning"}}
                def query(req):
                    return {
                        "findings": {"findings": [finding]}, "index": {"members": ["one.xhtml"]},
                        "read": {"text": "Wrd.", "start": 0, "member": "one.xhtml"},
                        "validate_edit": {"matched": True, "context": "Wrd."},
                        "verify": {"status": "awaiting_publication_decision", "candidate_sha256": expected},
                    }[req["action"]]
                yield query

        journal = self.journal()
        journal.qualify("probe")
        controller = Controller(self.drive, self.scope, Runtime(), report_only=False, journal=journal)
        controller.acquire()
        calls = []
        def reviewer(name, cfg, payload):
            calls.append((name, copy.deepcopy(payload)))
            return {"action": "assess", "outcome": "edit", "evidence": ["one.xhtml"],
                    "rationale": "Synthetic " + name, "edit": {"member": "one.xhtml", "start": 0,
                    "before": "Wrd", "after": "Word" if name == "codex" else "Ward"}}
        review = Review(controller, reviewer)
        for item, pair in (("book", ("codex", "agy")), ("deep", ("claude", "codex"))):
            src = cloud.identity(self.drive.meta(item))
            controller.entries[item] = dict(source=src, configuration=controller.configuration,
                state="pending", report={"action": "stage_repair", "behavior": {"effective": "release"}},
                operation={"action": "stage_repair", "status": "pending"})
            controller.save()
            review.set_pair(pair)
            first = review.review(item, "word")
            proposal = first["assessments"][0]["proposal_id"]
            row = review.review(item, "word", second=True)
            self.assertEqual([a["reviewer"] for a in row["assessments"]], list(pair))
            self.assertEqual(calls[-1][1]["history"], [])
            self.assertNotIn(proposal, json.dumps(calls[-1][1]))
            with tempfile.TemporaryDirectory() as d:
                exported = Path(d) / "proposal.json"
                review.export(item, "word", exported)
                self.assertEqual(json.loads(exported.read_text())["assessments"][0]["proposal_id"], proposal)
                approved = review.approve(item, "word", proposal, exported)
                self.assertEqual(approved["status"], "awaiting_publication_decision")
                with self.assertRaises(cloud.Conflict):
                    review.publication_decision(item, "word", "0" * 64, True)
                self.assertEqual(review.publication_decision(item,"word",expected,True)["status"], "publication_pending")
                self.service.objects[item][0]["version"] = "2"
                with self.assertRaises(cloud.Conflict):
                    review.approve(item, "word", proposal, exported)
        self.assertEqual({name for name, _ in calls}, {"agy", "claude", "codex"})

    def test_preview_batches_use_real_staging_and_cleanup_after_failure(self):
        import tempfile
        from pathlib import Path
        from epub_triage.colab_controller import Controller
        from epub_triage.colab_runtime import Runtime, WorkerPending
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = Runtime(database=root / "db", epubcheck_jar=root / "check.jar", temp_root=root)
            runtime.readiness = {"scan": {"ready": True}, "behavior_ready": True}
            before = list(self.service.writes)
            staged = []
            def simulated_worker(job, request):
                sessions = list(runtime.root.glob("job-*"))
                self.assertEqual(sessions, [job])
                self.assertEqual((job / "intake.epub").read_bytes(), b"benign fixture")
                self.assertLess((job / "intake.epub").stat().st_size, request["stage_bytes"])
                staged.append(job)
                if len(staged) == 1:
                    raise WorkerPending("injected monitor outage")
                return {"sha256": request["sha256"], "action": "leave", "status": "clean"}
            runtime.launch = simulated_worker
            try:
                controller = Controller(self.drive, self.scope, runtime, report_only=True, stage_mib=512)
                controller.select(("book", "deep"))
                result = controller.run()
                self.assertEqual(len(staged), 2)
                self.assertFalse(any(job.exists() for job in staged))
                self.assertIn("pending", result["summary"])
                self.assertEqual(self.service.writes, before)
            finally:
                runtime.close()
            self.assertEqual(list(root.iterdir()), [])

    def test_reopened_clean_decision_detects_replaced_source_and_engine(self):
        from epub_triage.colab_controller import Controller
        class Runtime:
            version = "engine-A"
            def configuration(self):
                return {"engine": self.version}
            def inspect(self, drive, scope, source, **unused):
                return {"sha256": source["sha256"], "action": "leave", "status": "clean"}
        r = Runtime()
        j = self.journal()
        j.qualify("probe")
        def open_session():
            return Controller(self.drive, self.scope, r, journal=j, report_only=False)
        first = open_session()
        first.acquire()
        first.select(("book",))
        first.run()
        self.service.objects["book"][0]["version"] = "2"
        reopened = open_session()
        before = len(self.service.writes)
        self.assertEqual(len(reopened.status()["books"]), 1)
        self.assertEqual(len(self.service.writes), before)
        reopened.acquire(takeover=True)
        self.assertEqual(reopened.run(resume=True)["books"][0]["state"], "stale")
        r.version = "engine-B"
        changed = open_session()
        changed.acquire(takeover=True)
        with self.assertRaises(cloud.Conflict):
            changed.run(resume=True)

    def test_gemini_tool_registration_cannot_qualify_text_only_client(self):
        from epub_triage.colab_gemini import messages_only
        base = {"contents": [{"role": "user", "parts": [{"text": "public marker"}]}]}
        self.assertIn("contents", messages_only(base))
        with self.assertRaises(ValueError):
            messages_only({**base, "tools": [{"functionDeclarations": [{"name": "unapproved"}]}]})

    def journal(self):
        return cloud.Journal(self.drive, self.scope, "journal", "user")

    def test_dedicated_evidence_upload_interruption_and_independent_expiry(self):
        self.service.objects["trace"][0]["properties"] = {"epubValidatorV5Evidence": "vault"}
        self.service.add("vault", "trace", "application/json", cloud.canonical(cloud.evidence_template("intake")))
        journal = self.journal()
        journal.qualify("probe")
        generation = journal.acquire("one")
        store = cloud.EvidenceStore(self.drive, self.scope, journal, "vault")
        data = [{"private_detailed_test_marker": 1234}]
        records = {}
        for item in ("book", "deep"):
            records[item] = {"source": cloud.identity(self.drive.meta(item)), "configuration": "cfg",
                             "state": "held", "trace": {"slot": item, "expires_at": 12345,
                             "sha256": cloud.stamp(data), "status": "evidence folder upload pending"}}
        journal.commit("one", generation, "cfg", records)
        self.service.failure = ("before", "vault")
        with self.assertRaises(cloud.DriveError):
            store.write("one", generation, records["book"], data)
        self.assertEqual(store.snapshot()[0]["traces"], {})
        store.recover("one", generation)
        stored = store.write("one", generation, records["book"], data)
        self.service.failure = ("after", "vault")
        with self.assertRaises(cloud.DriveError):
            store.write("one", generation, records["deep"], data)
        store.recover("one", generation)
        self.assertEqual(set(store.snapshot()[0]["traces"]), {"book", "deep"})
        self.assertNotIn("private_detailed_test_marker", json.dumps(journal.snapshot()[0]))
        store.expire("one", generation, stored, "book")
        self.assertEqual(set(store.snapshot()[0]["traces"]), {"deep"})
        self.assertEqual(journal.snapshot()[0]["books"]["book"]["state"], "held")

    def test_binary_staging_interruptions_and_occupied_slot(self):
        from pathlib import Path
        import tempfile
        j = self.journal()
        j.qualify("probe")
        g = j.acquire("one")
        self.service.add("binaryprobe", "trace", "application/octet-stream",
                         cloud.canonical(cloud.candidate_template("disposable")),
                         properties={"epubValidatorV5Candidate": "disposable"})
        qualified = {cloud.CandidateStore(self.drive, self.scope, j, "binaryprobe").qualify()}
        for phase, item in (("before", "book"), ("after", "deep")):
            slot = "slot" + item
            self.service.add(slot, "trace", "application/octet-stream",
                             cloud.canonical(cloud.candidate_template(item)),
                             properties={"epubValidatorV5Candidate": item})
            cs = cloud.CandidateStore(self.drive, self.scope, j, slot, qualified)
            source = cloud.identity(self.drive.meta(item))
            row = {"state": "pending", "source": source, "configuration": "cfg"}
            books = {**j.snapshot()[0]["books"], item: row}
            j.commit("one", g, "cfg", books)
            candidate = b"controlled rebuilt candidate"
            sha = hashlib.sha256(candidate).hexdigest()
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "edition.epub"
                path.write_bytes(candidate)
                with self.assertRaises(cloud.DriveError):
                    cs.store("one", g, row, path, "0" * 64)
                self.service.failure = (phase, slot)
                with self.assertRaises(cloud.DriveError):
                    cs.store("one", g, row, path, sha)
                cs.recover("one", g)
                current = j.snapshot()[0]["books"][item]
                if phase == "before":
                    self.assertEqual(current["candidate"]["status"], "staging_needs_retry")
                    cs.store("one", g, current, path, sha)
                else:
                    self.assertEqual(current["candidate"]["status"], "staged")
                before = len(self.service.writes)
                cs.store("one", g, current, path, sha)
                self.assertEqual(len(self.service.writes), before)
                self.assertEqual(self.service.objects[slot][1], candidate)
                path.write_bytes(b"different revision")
                with self.assertRaises(cloud.DriveError):
                    cs.store("one", g, row, path, hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(self.drive.meta(slot)["parents"], ["trace"])
                self.assertEqual(self.service.objects[slot][1], candidate)

    def test_delayed_binary_upload_is_fenced_before_takeover(self):
        from pathlib import Path
        import tempfile
        j = self.journal()
        j.qualify("probe")
        g = j.acquire("one")
        for item, tag in (("binaryprobe", "disposable"), ("reserved", "book")):
            self.service.add(item, "trace", "application/octet-stream",
                             cloud.canonical(cloud.candidate_template(tag)),
                             properties={"epubValidatorV5Candidate": tag})
        qualified = {cloud.CandidateStore(self.drive, self.scope, j, "binaryprobe").qualify()}
        cs = cloud.CandidateStore(self.drive, self.scope, j, "reserved", qualified)
        book = {"source": cloud.identity(self.drive.meta("book")), "configuration": "cfg", "state": "pending"}
        j.commit("one", g, "cfg", {"book": book})
        arrived, resume = threading.Event(), threading.Event()
        self.service.delay = ("old-upload", arrived, resume, "reserved")
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.epub"
            candidate.write_bytes(b"public test candidate")
            sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
            def upload():
                try:
                    cs.store("one", g, book, candidate, sha)
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=upload, name="old-upload")
            thread.start()
            try:
                self.assertTrue(arrived.wait(3))
                cs.recover("two", None, takeover=True)
                j.acquire("two", takeover=True)
                observed = self.service.objects["reserved"][1]
            finally:
                resume.set()
                thread.join(5)
            self.assertTrue(any(isinstance(e, cloud.Conflict) for e in errors), errors)
            self.assertEqual(self.service.objects["reserved"][1], observed)
            self.assertNotEqual(observed, candidate.read_bytes())

    def open_quarantine_lane(self):
        for item in ("left", "right"):
            self.service.add(item, "reports", cloud.FOLDER, properties={"epubValidatorV5Probe": "disposable"})
        self.service.add("scratch", "left", "application/octet-stream", b"probe",
                         properties={"epubValidatorV5Probe": "disposable"})
        self.service.objects["book"][0]["capabilities"]["canMoveItemWithinDrive"] = True
        journal = self.journal()
        journal.qualify("probe")
        lane = cloud.Quarantine(self.drive, self.scope, journal)
        lane.qualify("scratch", "left", "right")
        generation = journal.acquire("one")
        source = cloud.identity(self.drive.meta("book"))
        book = dict(source=source, state="pending", configuration="cfg",
                    operation=dict(id="op1", action="quarantine", status="pending",
                                   expected_sha256=source["sha256"]))
        journal.commit("one", generation, "cfg", {"book": book})
        return journal, lane, generation, book

    def test_interrupted_before_move_resumes_once(self):
        journal, lane, generation, book = self.open_quarantine_lane()
        self.service.physical_failure = ("before", "book")
        with self.assertRaises(cloud.DriveError):
            lane.dispatch("one", generation, book)
        self.assertEqual(self.drive.meta("book")["parents"], ["intake"])
        for _ in range(2):
            lane.recover("one", generation)
        self.assertEqual(journal.snapshot()[0]["books"]["book"]["state"], "complete")
        self.assertEqual(self.service.move_commits.count("book"), 1)

    def test_source_edit_and_occupied_destination_pause_only_the_operation(self):
        journal, lane, generation, book = self.open_quarantine_lane()
        self.service.add("occupied", "q", "application/epub+zip", b"earlier edition", "book.epub")
        with self.assertRaises(cloud.DriveError):
            lane.dispatch("one", generation, book)
        self.assertEqual(self.service.objects["occupied"][1], b"earlier edition")
        self.service.objects["occupied"][0]["name"] = "different.epub"
        self.service.objects["book"][0]["version"] = "2"
        with self.assertRaises(cloud.Conflict):
            lane.dispatch("one", generation, book)
        self.assertEqual(self.drive.meta("book")["parents"], ["intake"])
        self.assertNotIn("book", self.service.move_commits)
        self.assertFalse(journal.snapshot()[0].get("in_flight_physical"))

    def test_move_receipt_lost_recognized_once(self):
        journal, lane, generation, book = self.open_quarantine_lane()
        self.service.physical_failure = ("after", "book")
        with self.assertRaises(cloud.DriveError):
            lane.dispatch("one", generation, book)
        self.assertEqual(self.drive.meta("book")["parents"], ["q"])
        for _ in range(2):
            lane.recover("one", generation)
        self.assertEqual(journal.snapshot()[0]["books"]["book"]["state"], "complete")
        self.assertEqual(self.service.move_commits.count("book"), 1)

    def test_queued_move_cannot_commit_after_new_owner(self):
        journal, lane, generation, book = self.open_quarantine_lane()
        arrived, resume = threading.Event(), threading.Event()
        self.service.delay = ("old-move", arrived, resume, "book")
        errors = []
        def dispatch():
            try:
                lane.dispatch("one", generation, book)
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=dispatch, name="old-move")
        thread.start()
        try:
            self.assertTrue(arrived.wait(3))
            with self.assertRaises(cloud.Conflict):
                journal.acquire("two", takeover=True)
            lane.recover("two", None, takeover=True)
            self.assertGreater(journal.acquire("two", takeover=True), generation)
            before = self.service.move_commits.count("book")
        finally:
            resume.set()
            thread.join(5)
        self.assertTrue(any(isinstance(e, cloud.Conflict) for e in errors), errors)
        self.assertEqual(self.service.move_commits.count("book"), before)
        self.assertEqual(journal.snapshot()[0]["writer"], "two")

    def test_server_ignoring_cas_cannot_enable_writes(self):
        journal = self.journal()
        self.service.honor_match = False
        with self.assertRaises(cloud.DriveError):
            journal.qualify("probe")
        with self.assertRaises(cloud.DriveError):
            journal.acquire("alpha")
        self.assertNotIn("journal", self.service.writes)

    def test_simultaneous_first_acquisition_has_one_winner(self):
        journals = [self.journal(), self.journal()]
        for j in journals:
            j.qualify("probe")
        race = threading.Barrier(2)
        original = self.drive.patch_journal
        def together(item, data, etag):
            if item == "journal":
                race.wait(timeout=3)
            return original(item, data, etag)
        self.drive.patch_journal = together
        outcomes = []
        def acquire(index):
            try:
                outcomes.append(journals[index].acquire(str(index)))
            except cloud.Conflict:
                outcomes.append("rejected")
        threads = [threading.Thread(target=acquire, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertCountEqual(outcomes, [1, "rejected"])
        self.assertEqual(journals[0].snapshot()[0]["generation"], 1)

    def test_shared_drive_selection_uses_scoped_listing(self):
        for meta, data in self.service.objects.values():
            meta["driveId"] = "team"
        requests = []
        original = self.service.request
        def log(method, url, **kwargs):
            if url.endswith("/files"):
                requests.append(kwargs.get("params", {}))
            return original(method, url, **kwargs)
        self.service.request = log
        result, denied = self.scope.select(self.drive, ("sub",))
        self.assertEqual([item["id"] for item in result], ["deep"])
        self.assertFalse(denied)
        self.assertTrue(requests)
        self.assertTrue(all(p.get("driveId") == "team" and p.get("corpora") == "drive" for p in requests))

    def test_delayed_old_journal_write_rejected_after_takeover(self):
        one, two = self.journal(), self.journal()
        one.qualify("probe")
        two.qualify("probe")
        old = one.acquire("one")
        with self.assertRaises(cloud.Conflict):
            two.acquire("two")
        arrived, resume = threading.Event(), threading.Event()
        self.service.delay = ("old-request", arrived, resume)
        errors = []
        def submit():
            try:
                one.commit("one", old, "configuration", {"stale": {}})
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=submit, name="old-request")
        thread.start()
        try:
            self.assertTrue(arrived.wait(3))
            self.assertGreater(two.acquire("two", takeover=True), old)
        finally:
            resume.set()
            thread.join(4)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], cloud.Conflict)
        state, _, _ = two.snapshot()
        self.assertEqual(state["writer"], "two")
        self.assertNotIn("stale", state["books"])

    def test_journal_response_loss_can_be_inspected_before_retry(self):
        journal = self.journal()
        journal.qualify("probe")
        generation = journal.acquire("one")
        for phase, seen in (("before", {}), ("after", {"book": {"decision": "hold"}})):
            self.service.failure = phase
            with self.assertRaises(cloud.DriveError):
                journal.commit("one", generation, "cfg", {"book": {"decision": "hold"}})
            before = len(self.service.writes)
            fresh = self.journal()
            self.assertEqual(fresh.snapshot()[0]["books"], seen)
            self.assertEqual(len(self.service.writes), before)


class StaticTimeout(unittest.TestCase):
    def test_elapsed_process_deadline_becomes_pending(self):
        import tempfile
        import time
        from pathlib import Path
        from unittest.mock import patch
        from epub_triage import backend, colab_worker
        from epub_triage.colab_runtime import Runtime, WorkerPending

        run_process = backend.bounded_worker
        def slow_static_worker(command, timeout):
            self.assertIn("inspect", command)
            return run_process(["/bin/sleep", "2"], 0.05)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            engine = backend.Backend({"epubcheck_jar": base / "jar"}, base)
            engine.epoch = int(time.time())
            with patch.object(backend, "bounded_worker", slow_static_worker):
                reply = colab_worker.static_reply(engine.inspect, base / "book", {})
            self.assertEqual(reply, {"pending": "static_timeout", "operation": "inspect"})
            runtime = Runtime(database=base, epubcheck_jar=base / "jar", temp_root=base)
            try:
                with runtime.job() as (job, request):
                    with patch("epub_triage.colab_runtime.bounded_worker",
                               return_value=(0, json.dumps(reply).encode(), b"fixture-only")):
                        with self.assertRaisesRegex(WorkerPending, "timed out during inspect"):
                            runtime.launch(job, {**request, "operation": "inspect"})
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
