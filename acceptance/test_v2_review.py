"""Independent Linux checks using benign books and controlled validator failures."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from acceptance.v2_fixtures import write_book
from acceptance.behavior_double import FixtureReader

from epub_triage import cli, repair_rules, worker
from epub_triage.archive import inventory

LIMITS = {key: bounds[0] for key, bounds in cli.DEFAULT_LIMITS.items()}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(path):
    result = {}
    for p in sorted(path.rglob("*")):
        info = p.stat()
        result[str(p.relative_to(path))] = (
            info.st_ino,
            info.st_mode,
            info.st_mtime_ns,
            sha(p) if p.is_file() else None,
        )
    return result


class EvidenceRules(unittest.TestCase):
    def evidence(self, **settings):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = write_book(base / "input.epub", **settings)
            parts = base / "members"
            parts.mkdir()
            members = inventory(archive, parts, LIMITS)
            edits = repair_rules.broader(members)
            for edit in edits:
                start, end = edit["byte_span"]
                data = members[edit["member"]].read_bytes()
                self.assertEqual(data[start:end], edit["before"].encode())
                self.assertEqual(
                    hashlib.sha256(data).hexdigest(), edit["member_sha256"]
                )
            return edits, repair_rules.signature_review(members, edits)

    def test_unique_reference_and_stale_fragment(self):
        edits, _ = self.evidence(case=True)
        self.assertEqual(
            [(e["member"], e["before"], e["after"]) for e in edits],
            [("nav.xhtml", "Text.xhtml#start", "text.xhtml#start")],
        )
        self.assertEqual(self.evidence(case=True, stale_fragment=True)[0], [])
        self.assertEqual(self.evidence(case=True, competing=True)[0], [])

    def test_identifier_corroboration_and_conflict(self):
        edits, _ = self.evidence(metadata="urn:example:one")
        self.assertEqual(
            [(e["member"], e["before"], e["after"]) for e in edits],
            [("book.opf", "PUB", "pub")],
        )
        self.assertEqual(self.evidence(metadata="urn:example:other")[0], [])

    def test_signed_reference_and_heuristic(self):
        edits, signs = self.evidence(case=True, layout=True, signed=True)
        self.assertTrue(edits)
        self.assertEqual(signs[0]["impact"], "affected")
        self.assertIn("nav.xhtml", json.dumps(signs[0]))
        self.assertEqual(self.evidence(warning=True)[0], [])

    def test_unresolved_signature_reference_withholds_even_packaging(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            book = write_book(base / "signed.epub", layout=True)
            with ZipFile(book, "a") as archive:
                archive.writestr(
                    "META-INF/signatures.xml",
                    '<signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
                    '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>'
                    '<Reference URI="#indirect"/></SignedInfo></Signature></signatures>',
                )
            output = base / "derivative.epub"
            plan = repair_rules.plan(book, LIMITS, "mechanical", base, output)
            self.assertEqual(plan["review"][0]["impact"], "unknown")
            self.assertEqual(plan["review"][0]["references"][0]["uri"], "#indirect")
            self.assertEqual(plan["review"][0]["proposed_edits"], ["M1"])
            self.assertFalse(output.exists())

    def test_writer_drift_in_edited_member_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            book = write_book(root / "book.epub", case=True)
            candidate = root / "candidate.epub"
            original_build = repair_rules.Layout.build

            def altered(layout, path, members, edits):
                hashes = original_build(layout, path, members, edits)
                with ZipFile(path) as z:
                    payloads = [(info, z.read(info)) for info in z.infolist()]
                with ZipFile(path, "w") as z:
                    for info, data in payloads:
                        if info.filename == "nav.xhtml":
                            data = data.replace(b"Chapter one", b"Chapter two")
                            if isinstance(hashes, dict):
                                hashes["nav.xhtml"] = hashlib.sha256(data).hexdigest()
                        z.writestr(info, data)
                return hashes

            with patch.object(repair_rules.Layout, "build", altered):
                result = repair_rules.plan(book, LIMITS, "broader", root, candidate)
            self.assertFalse(result.get("built"), result)


class ControlledWorker:
    # Only test process injection. Actual parser, rules, writer and supervisor run.
    calls = []
    candidates = set()
    fault = None

    def __init__(self, config, private):
        self.private = private

    def preflight(self):
        if type(self).fault == "preflight":
            raise RuntimeError("unavailable scanner")
        return {}

    def _inspect(self, path, limits, occurrences):
        is_candidate = str(path) in self.candidates
        self.calls.append(("verify" if is_candidate else "inspect", sha(path)))

        def quality(book, content):
            with ZipFile(book) as z:
                m = z.getinfo("mimetype")
                if m.header_offset or m.compress_type:
                    content.add("verified", "PKG-006", "Mimetype layout", None)

        with tempfile.TemporaryDirectory(dir=self.private) as tmp, patch.object(
            worker, "scan", side_effect=lambda paths: [None] * len(paths)
        ), patch.object(worker, "quality_check", quality):
            result = worker.inspect(path, limits, Path(tmp), occurrences=occurrences)
        if is_candidate and type(self).fault:
            fault = type(self).fault
            if fault == "dead":
                raise RuntimeError("verifier unavailable")
            if fault in {"incomplete", "active"}:
                result["security"] = {
                    "complete": fault == "active",
                    "findings": [
                        {
                            "kind": fault,
                            "code": "controlled",
                            "detail": "controlled fault",
                        }
                    ],
                }
                result["quality"]["complete"] = False
            if fault == "new":
                result["quality"]["findings"].append(
                    {
                        "kind": "verified",
                        "code": "broken_navigation_target",
                        "member": "nav.xhtml",
                        "detail": "Missing navigation document Text.xhtml",
                        "location": "a different navigation node",
                    }
                )
        return result

    def inspect(self, path, limits):
        return self._inspect(path, limits, False)

    def inspect_repair(self, path, limits):
        return self._inspect(path, limits, True)

    def plan_repair(self, path, limits, profile, candidate=None):
        self.calls.append(("plan" if candidate is None else "build", sha(path)))
        if candidate:
            self.candidates.add(str(candidate))
        with tempfile.TemporaryDirectory(dir=self.private) as tmp:
            result = repair_rules.plan(path, limits, profile, Path(tmp), candidate)
        return result


class Workflow(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.books = self.base / "books"
        self.out = self.books / "repaired"
        self.intake = self.base / "intake"
        self.queue = self.base / "queue.sqlite"
        self.config = self.base / "config.toml"
        keys = dict(
            folder=self.books,
            quarantine=self.base / "q",
            repair=self.intake,
            repaired_output=self.out,
            queue=self.queue,
            database=self.base / "db",
            epubcheck_jar=self.base / "checker.jar",
        )
        self.config.write_text(
            "".join(f"{k}={json.dumps(str(v))}\n" for k, v in keys.items())
        )
        ControlledWorker.calls.clear()
        ControlledWorker.candidates.clear()
        ControlledWorker.fault = None
        readers = patch("epub_triage.behavior.ReaderBackend", FixtureReader)
        readers.start()
        self.addCleanup(readers.stop)
        self.mock = patch.object(cli, "Backend", ControlledWorker)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def run_cli(self, mode, *args, expected=1):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = cli.main(
                [*([mode] if mode else []), "--config", str(self.config), *args]
            )
        self.assertEqual(rc, expected, (stdout.getvalue(), stderr.getvalue()))
        self.assertTrue(stderr.getvalue())
        return [json.loads(line) for line in stdout.getvalue().splitlines()]

    def test_selection_preview_versions_and_integrity(self):
        old = write_book(self.books / "old.epub", layout=True)
        fresh = write_book(
            self.books / "fresh.epub", layout=True, case=True, warning=True
        )
        damaged = write_book(self.books / "damaged.epub", layout=True)
        self.run_cli(None, old.name, damaged.name)
        self.assertFalse(self.out.exists())
        before = tree(self.base)
        preview = self.run_cli("scan", "--repair", "--report-only", fresh.name)
        self.assertIn("unverified", json.dumps(preview))
        self.assertIn("M1", json.dumps(preview))
        self.assertEqual(before, tree(self.base))
        preview = self.run_cli("repair", "--report-only")
        self.assertEqual(len(preview), 2)
        self.assertEqual(before, tree(self.base))
        self.assertFalse(
            any(call[0] in {"verify", "build"} for call in ControlledWorker.calls)
        )
        self.assertEqual(len(self.run_cli("scan", "--repair", fresh.name)), 1)
        (partial,) = self.out.glob("*.epub")
        with ZipFile(partial) as z:
            self.assertIn(b"Text.xhtml#start", z.read("nav.xhtml"))
        (self.intake / damaged.name).write_bytes(b"different copy")
        reports = self.run_cli("repair")
        self.assertIn("hash", json.dumps(reports).lower())
        self.assertEqual(len(list(self.out.glob("*.epub"))), 2)
        ControlledWorker.calls.clear()
        self.run_cli("repair")
        self.assertFalse(any(c[0] == "build" for c in ControlledWorker.calls))
        ControlledWorker.calls.clear()
        reports = self.run_cli("repair", "--profile", "broader")
        versions = list(self.out.glob("*.epub"))
        self.assertEqual(len(versions), 3, reports)
        self.assertIn(("build", sha(fresh)), ControlledWorker.calls)
        self.assertEqual(sha(fresh), sha(self.intake / fresh.name))
        self.assertTrue(partial.exists())
        (final,) = [
            p
            for p in versions
            if p != partial
            and p.read_bytes() != old.read_bytes()
            and b"legible prose" in p.read_bytes()
        ]
        self.assertEqual(final.stem, sha(final))
        with ZipFile(fresh) as a, ZipFile(final) as b:
            for n in a.namelist():
                expected = a.read(n)
                if n == "nav.xhtml":
                    expected = expected.replace(
                        b'"Text.xhtml#start"', b'"text.xhtml#start"'
                    )
                self.assertEqual(expected, b.read(n))
        self.assertIn("suspected_ocr_corruption", json.dumps(reports))
        with sqlite3.connect(self.queue) as db:
            (audit,) = db.execute(
                "SELECT report FROM repair_attempts WHERE decision='accepted' "
                "AND report LIKE ?",
                ("%" + sha(final) + "%",),
            ).fetchone()
            for token in (
                sha(fresh),
                sha(final),
                "R1",
                "M1",
                "broader",
                "Text.xhtml#start",
            ):
                self.assertIn(token, audit)
        ordinary = self.run_cli(None, "--report-only")
        self.assertEqual(
            {r["path"] for r in ordinary}, {p.name for p in (old, fresh, damaged)}
        )

    def test_signed_book_whole_plan_and_ambiguous_inventory(self):
        signed = write_book(
            self.books / "signed.epub", case=True, layout=True, signed=True
        )
        write_book(self.books / "ambiguous.epub", case=True, ambiguous=True)
        write_book(self.books / "heuristic.epub", warning=True)
        reports = self.run_cli("scan", "--repair", "--profile", "broader")
        (signed_record,) = [r for r in reports if r["path"] == signed.name]
        for token in ("affected", "nav.xhtml", "M1", "R1"):
            self.assertIn(token, json.dumps(signed_record))
        self.assertFalse(list(self.out.glob("*.epub")))
        self.assertTrue(signed.exists())
        self.assertTrue((self.base / "q" / "ambiguous.epub").exists())

    def test_candidate_failure_paths_and_operational_stop(self):
        p = write_book(self.books / "multi.epub", layout=True, case=True)
        self.run_cli(None, p.name)
        for fault in ("incomplete", "active", "new", "dead", "preflight"):
            with self.subTest(fault=fault):
                ControlledWorker.fault = fault
                # Each scenario starts with the same unattempted v1 queue.
                original = self.queue.read_bytes()
                try:
                    result = self.run_cli(
                        "repair",
                        "--profile",
                        "broader",
                        expected=2 if fault in {"dead", "preflight"} else 1,
                    )
                    self.assertFalse(list(self.out.glob("*.epub")), result)
                    self.assertEqual(sha(p), sha(self.intake / p.name))
                finally:
                    self.queue.write_bytes(original)

    def test_restart_after_link_and_collision_and_duplicate(self):
        from epub_triage.repair_state import RepairState

        first = write_book(self.books / "first.epub", layout=True, case=True)
        self.run_cli(None, first.name)
        # Lose the process after durable object publication but before cleanup.
        with patch.object(
            RepairState, "clean", side_effect=RuntimeError("injected interruption")
        ):
            self.run_cli("repair", expected=2)
        (obj,) = self.out.glob("*.epub")
        self.assertEqual(obj.stem, sha(obj))
        self.run_cli("repair")
        self.assertEqual(list(self.out.glob("*.part")), [])
        # Preoccupy the broader object's name with distinct complete bytes.
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "broader.epub"
            repair_rules.plan(first, LIMITS, "broader", Path(temp), sample)
            broader = self.out / (sha(sample) + ".epub")
        broader.write_bytes(b"pre-existing occupant")
        self.run_cli("repair", "--profile", "broader")
        self.assertEqual(broader.read_bytes(), b"pre-existing occupant")
        self.assertEqual(obj.stem, sha(obj))
        broader.unlink()
        self.run_cli("repair", "--profile", "broader", expected=0)
        second = write_book(self.books / "second.epub", layout=True, case=True)
        self.run_cli(None, second.name)
        self.run_cli("repair", "--profile", "broader", expected=0)
        self.assertEqual(len(list(self.out.glob("*.epub"))), 2)
        with sqlite3.connect(self.queue) as db:
            rows = db.execute(
                "SELECT path,sha256 FROM repair_versions WHERE ready=1"
            ).fetchall()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(sha(Path(path)) == digest for path, digest in rows))

    def test_interrupted_prelink_and_two_process_retry(self):
        import multiprocessing
        from epub_triage.repair_state import RepairState

        write_book(self.books / "race.epub", layout=True, case=True)
        self.run_cli(None)
        with patch.object(
            RepairState, "finish", side_effect=RuntimeError("before link")
        ):
            self.run_cli("repair", expected=2)
        self.assertFalse(list(self.out.glob("*.epub")))
        ctx = multiprocessing.get_context("fork")
        out = ctx.Queue()

        def run_one():
            try:
                r = self.run_cli("repair", "--profile", "broader", expected=0)
                out.put(r[0]["decision"])
            except Exception as exc:
                out.put(str(exc))

        processes = [ctx.Process(target=run_one) for _ in range(2)]
        for proc in processes:
            proc.start()
        for proc in processes:
            proc.join(20)
            self.assertEqual(proc.exitcode, 0)
        self.assertEqual(
            sorted(out.get(timeout=2) for _ in processes), ["accepted", "unchanged"]
        )
        with sqlite3.connect(self.queue) as db:
            rows = db.execute(
                "select sha256,path,ready from repair_versions order by sequence"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertTrue(
            all(ready and sha(Path(path)) == digest for digest, path, ready in rows)
        )

    def test_relevant_rule_revision_and_latest_regression(self):
        from epub_triage import repair

        p = write_book(self.books / "partial.epub", layout=True, case=True)
        self.run_cli(None)
        self.run_cli("repair")
        (partial,) = self.out.glob("*.epub")
        saved = partial.read_bytes()
        with patch.dict(repair.RULE_REVISIONS, M1="2"):
            ControlledWorker.calls.clear()
            self.run_cli("repair")
            self.assertIn(("build", sha(p)), ControlledWorker.calls)
            self.assertEqual(list(self.out.glob("*.epub")), [partial])

        class Regress(ControlledWorker):
            def inspect_repair(self, path, limits):
                result = super().inspect_repair(path, limits)
                if str(path) in self.candidates:
                    result["quality"]["findings"].append(
                        {
                            "kind": "verified",
                            "code": "PKG-006",
                            "detail": "Mimetype layout",
                        }
                    )
                return result

        with patch.object(cli, "Backend", Regress):
            (r,) = self.run_cli("repair", "--profile", "broader")
        self.assertEqual(r["decision"], "rejected")
        self.assertIn("latest", r["reason"])
        self.assertEqual(partial.read_bytes(), saved)

    def test_noop_rejection_and_batch_continuation(self):
        a = write_book(self.books / "a.epub", layout=True)
        write_book(self.books / "b.epub", layout=True, case=True)
        self.run_cli(None)

        class Noop(ControlledWorker):
            def plan_repair(self, source, limits, profile, candidate=None):
                response = super().plan_repair(source, limits, profile, candidate)
                if candidate and sha(source) == sha(a):
                    candidate.write_bytes(source.read_bytes())
                    response["candidate_sha256"] = sha(candidate)
                return response

        with patch.object(cli, "Backend", Noop):
            result = self.run_cli("repair")
        self.assertEqual([r["decision"] for r in result], ["rejected", "accepted"])
        self.assertEqual(len(list(self.out.glob("*.epub"))), 1)

    def test_changed_intake_can_be_restaged_and_queue_hash_is_checked(self):
        book = write_book(self.books / "entry.epub", layout=True)
        self.run_cli(None)
        old_intake = self.intake / book.name
        old_intake.write_bytes(b"operator replacement")
        (r,) = self.run_cli("repair")
        self.assertEqual(r["decision"], "hash-mismatch")
        (r,) = self.run_cli("scan", "--repair", book.name)
        self.assertEqual(r["repair"]["decision"], "accepted")
        self.assertEqual(old_intake.read_bytes(), b"operator replacement")
        self.assertEqual(sha(Path(r["destination"])), sha(book))
        with sqlite3.connect(self.queue) as db:
            db.execute(
                "UPDATE repair_queue SET sha256=? WHERE repair_copy=?",
                ("0" * 64, r["destination"]),
            )
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            cli.main(["repair", "--config", str(self.config)])
        decisions = [json.loads(row)["decision"] for row in out.getvalue().splitlines()]
        self.assertFalse(set(decisions) & {"accepted", "unchanged"})
        self.assertEqual(len(list(self.out.glob("*.epub"))), 1)

    def test_latest_bytes_and_report_only_preflight_failure(self):
        p = write_book(self.books / "one.epub", layout=True)
        self.run_cli(None)
        self.run_cli("repair", expected=0)
        (obj,) = self.out.glob("*.epub")
        obj.chmod(0o600)
        obj.write_bytes(b"externally replaced")
        (r,) = self.run_cli("repair")
        self.assertEqual(r["decision"], "review")
        self.assertIn("hash", r["reason"])
        before = tree(self.base)
        ControlledWorker.fault = "preflight"
        self.run_cli("scan", "--repair", "--report-only", p.name, expected=2)
        self.assertEqual(before, tree(self.base))

    def test_standalone_across_v1_roots_and_two_identical_lineages(self):
        p = write_book(self.books / "same.epub", layout=True)
        other = self.base / "other"
        write_book(other / p.name, layout=True)
        self.run_cli(None)
        self.run_cli(None, "--folder", str(other))
        first = self.run_cli("repair", expected=0)
        self.assertEqual({r["source"] for r in first}, {str(p), str(other / p.name)})
        self.assertEqual({r["decision"] for r in first}, {"accepted"})
        self.assertEqual(len(list(self.out.glob("*.epub"))), 1)

    def test_empty_queue_preview_and_unsupported_live_wal(self):
        p = write_book(self.books / "example.epub", layout=True)
        before = tree(self.base)
        self.assertEqual(self.run_cli("repair", "--report-only", expected=0), [])
        (r,) = self.run_cli("scan", "--repair", "--report-only", p.name)
        self.assertEqual(r["repair"]["decision"], "planned")
        self.assertEqual(before, tree(self.base))
        self.run_cli(None)
        with sqlite3.connect(self.queue) as owner:
            owner.execute("PRAGMA journal_mode=WAL")
            owner.execute("CREATE TABLE operator_note (msg TEXT)")
            owner.execute("INSERT INTO operator_note VALUES ('committed in WAL')")
            owner.commit()
            before = tree(self.base)
            self.run_cli("repair", "--report-only", expected=2)
            self.assertEqual(before, tree(self.base))

    def test_process_dies_between_link_and_ready_commit(self):
        import multiprocessing
        import os

        write_book(self.books / "interrupt.epub", layout=True)
        self.run_cli(None)
        link = os.link

        def die_after_link(*args, **kwargs):
            link(*args, **kwargs)
            os._exit(81)

        def publish():
            with patch("epub_triage.repair_state.os.link", die_after_link):
                self.run_cli("repair", expected=0)

        child = multiprocessing.get_context("fork").Process(target=publish)
        child.start()
        child.join(20)
        self.assertEqual(child.exitcode, 81)
        with sqlite3.connect(self.queue) as db:
            self.assertEqual(
                db.execute("SELECT ready FROM repair_versions").fetchall(), [(0,)]
            )
        (path,) = self.out.glob("*.epub")
        self.assertEqual(path.stem, sha(path))
        (result,) = self.run_cli("repair", expected=0)
        self.assertEqual(result["latest"]["sha256"], path.stem)
        with sqlite3.connect(self.queue) as db:
            self.assertEqual(
                db.execute("SELECT ready,temp_name FROM repair_versions").fetchall(),
                [(1, None)],
            )

    def test_mismatch_during_pending_publication_leaves_output_unpublished(self):
        from epub_triage.repair_state import RepairState

        p = write_book(self.books / "pending.epub", layout=True)
        self.run_cli(None)
        with patch.object(
            RepairState, "finish", side_effect=RuntimeError("interrupt before link")
        ):
            self.run_cli("repair", expected=2)
        self.assertFalse(list(self.out.glob("*.epub")))
        staged = self.intake / p.name
        staged.write_bytes(b"replacement intake")
        (report,) = self.run_cli("repair")
        self.assertEqual(report["decision"], "hash-mismatch")
        self.assertFalse(list(self.out.glob("*.epub")))
        staged.write_bytes(p.read_bytes())
        (report,) = self.run_cli("repair", expected=0)
        self.assertEqual(report["latest"]["sha256"], sha(next(self.out.glob("*.epub"))))
