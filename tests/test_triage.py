"""Harmless policy fixtures, controlled worker evidence, and disposition faults."""

from contextlib import closing, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import time
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from acceptance.behavior_double import FixtureReader

from epub_triage.archive import BookError, inventory
from epub_triage.backend import Backend, age_is_fresh
from epub_triage.cli import configuration, main, validate_result
from epub_triage.content import Content, finding
from epub_triage.state import State
from epub_triage import worker

LIMITS = {"max_entries": 50, "max_member_bytes": 8192, "max_expanded_bytes": 32768}
XHTML = '<html xmlns="http://www.w3.org/1999/xhtml"><body>{}</body></html>'


def write_epub(path, body="<p>Friendly test book</p>", additional=None):
    entries = {
        "mimetype": b"application/epub+zip",
        "book.xhtml": XHTML.format(body).encode("utf-8"),
    }
    entries.update(additional or {})
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def inspect_test(snapshot, limits):
    with tempfile.TemporaryDirectory() as output:
        try:
            members = inventory(snapshot, Path(output), limits)
        except BookError as error:
            return {"security": {"complete": False, "findings": [
                        finding(error.kind, error.code, str(error), error.member)]},
                    "quality": {"complete": False, "findings": []}}
        inspector = Content(members)
        inspector.inspect()
        if "positive.xml" in members:
            inspector.security.append(finding("malware", "malware_signature", "Test.Double"))
        complete = not any(item["kind"] == "incomplete" for item in inspector.security)
        return {"security": {"complete": complete, "findings": inspector.security},
                "quality": {"complete": complete, "findings": inspector.quality}}


class TestBackend:
    def __init__(self, config, private):
        pass

    def preflight(self):
        return {}

    def inspect(self, snapshot, limits):
        return inspect_test(snapshot, limits)


class PolicyTests(unittest.TestCase):
    def test_publisher_age_boundaries(self):
        for seconds, expected in [(-1, False), (0, True), (259199, True), (259200, True), (259201, False)]:
            self.assertEqual(age_is_fresh(500000, now=500000 + seconds), expected)

    def test_cvd_inner_header_prevents_timestamp_substitution(self):
        outer = b"ClamAV-VDB:stamp:1:2:3:checksum:signature:publisher:500000".split(b":")
        inner = b"ClamAV-VDB:stamp:1:2:3:X:X:publisher:500000\n"
        with tempfile.TemporaryDirectory() as directory:
            cvd = Path(directory) / "daily.cvd"
            with cvd.open("wb") as payload:
                payload.write(b" ".join([b":".join(outer), b""]).ljust(512))
                with tarfile.open(fileobj=payload, mode="w:gz") as archive:
                    entry = tarfile.TarInfo("daily.info")
                    entry.size = len(inner)
                    archive.addfile(entry, io.BytesIO(inner))
            Backend.verify_inner_epoch(cvd, outer)
            outer[-1] = b"500001"
            with self.assertRaisesRegex(RuntimeError, "authenticated payload"):
                Backend.verify_inner_epoch(cvd, outer)

    def test_malformed_worker_evidence_is_operational(self):
        for response in ([], {"security": {"complete": True, "findings": [
            {"kind": [], "detail": "Bad", "code": "bad"}]}, "quality": {}}):
            with self.assertRaises(RuntimeError):
                validate_result(response)

    def test_link_remote_and_unlisted_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "book.epub"
            write_epub(path, '<a href="https://example.invalid/a">ordinary link</a>', {
                "navigation.ncx": b'<ncx><content src="https://example.invalid/a"/></ncx>',
                "unused.css": b'@namespace url("https://namespace.invalid/ns"); p { color: red; }',
            })
            self.assertEqual(inspect_test(path, LIMITS)["security"]["findings"], [])
            write_epub(path, '<img src="//example.invalid/p.jpg"/>', {
                "unused.css": b'@import "https://example.invalid/style.css";',
                "unlisted.js": b'/* harmless scripted resource fixture */',
            })
            findings = inspect_test(path, LIMITS)["security"]["findings"]
            self.assertEqual({item["member"] for item in findings},
                             {"book.xhtml", "unlisted.js", "unused.css"})
            write_epub(path, additional={"bad.css": b"broken {" + b'p { background: url("x\n") }'})
            findings = inspect_test(path, LIMITS)["security"]["findings"]
            self.assertTrue(any(item["code"] == "css_parse" for item in findings))

    def test_confirmed_quarantine_preserves_static_quality_without_epubcheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            path = scratch / "book.epub"
            write_epub(path, '<script>/* harmless fixture */</script><nav><a href="#missing">chapter</a></nav>')
            with patch.object(worker, "scan", side_effect=lambda paths: [None] * len(paths)), \
                    patch.object(worker, "quality_check", side_effect=RuntimeError("EPUBCheck unavailable")) as validator:
                result = worker.inspect(path, LIMITS, scratch=scratch)
            validator.assert_not_called()
            self.assertTrue(result["security"]["complete"])
            self.assertEqual(result["security"]["findings"][0]["kind"], "active")
            self.assertFalse(result["quality"]["complete"])
            self.assertIn("skipped", result["quality"]["incomplete_reason"])
            self.assertEqual(result["quality"]["findings"][0]["code"], "broken_navigation_fragment")
            self.assertEqual(validate_result(result), result)

    def test_scanner_batches_archive_and_members_and_keeps_raw_failure_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            book = root / "book.epub"
            accepted, rejected = root / "accepted", root / "rejected"
            accepted.mkdir()
            rejected.mkdir()
            write_epub(book)
            with patch.object(worker, "scan", side_effect=lambda paths: [None] * len(paths)) as scanner, \
                    patch.object(worker, "quality_check"):
                report = worker.inspect(book, LIMITS, scratch=accepted)
            scanner.assert_called_once_with([book, accepted / "members/000000", accepted / "members/000001"])
            self.assertTrue(report["security"]["complete"])
            write_epub(book, additional={"../bad.xhtml": b"<html/>"})
            detection = finding("malware", "malware_signature", "Test.Double")
            with patch.object(worker, "scan", return_value=[detection]) as scanner:
                report = worker.inspect(book, LIMITS, scratch=rejected)
            scanner.assert_called_once_with([book])
            self.assertEqual({item["kind"] for item in report["security"]["findings"]}, {"malware", "unsafe"})

    def test_physical_archive_limit_and_dangerous_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "book.epub"
            write_epub(path, additional={"../outside.xhtml": b"<html/>"})
            self.assertEqual(inspect_test(path, LIMITS)["security"]["findings"][0]["kind"], "unsafe")
            write_epub(path)
            limits = {**LIMITS, "max_expanded_bytes": 5}
            evidence = inspect_test(path, limits)["security"]
            self.assertEqual(evidence["findings"][0]["code"], "expansion_limit")
            self.assertFalse(evidence["complete"])


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.intake = self.base / "books"
        self.intake.mkdir()
        self.quarantine = self.intake / "quarantine"
        self.repair = self.intake / "repair"
        self.queue = self.base / "queue.sqlite"
        self.config = self.base / "config.toml"
        self.config.write_text('folder = "books"\nquarantine = "books/quarantine"\nrepair = "books/repair"\n'
                               'queue = "queue.sqlite"\ndatabase = "db"\nepubcheck_jar = "epubcheck.jar"\n')

    @patch("epub_triage.behavior.ReaderBackend", FixtureReader)
    def cli(self, *args, backend=TestBackend):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch("epub_triage.cli.Backend", backend):
            code = main(["--config", str(self.config), *map(str, args)])
        return code, [json.loads(line) for line in out.getvalue().splitlines()], err.getvalue()

    def test_timeouts_configured_with_bounds_and_inspection_deadline_forwarded(self):
        self.assertEqual(configuration(self.config, None)["readiness_timeout"], 180)
        self.assertEqual(configuration(self.config, None)["inspection_timeout"], 300)
        with self.config.open("a") as stream:
            stream.write("readiness_timeout = 1200\ninspection_timeout = 2400\n")
        configured = configuration(self.config, None)
        self.assertEqual(configured["readiness_timeout"], 1200)
        with tempfile.TemporaryDirectory() as temporary:
            backend = Backend(configured, Path(temporary))
            backend.epoch = int(time.time())
            with patch.object(backend, "invoke", return_value={}) as invoke:
                backend.inspect(self.intake / "book.epub", LIMITS)
            self.assertEqual(invoke.call_args.kwargs, {"timeout": 2400})
        text = self.config.read_text().replace("2400", "3601")
        self.config.write_text(text)
        self.assertEqual(self.cli()[0], 2)

    def test_preview_selection_disposition_and_idempotency(self):
        nested = self.intake / "nested"
        nested.mkdir()
        write_epub(self.intake / "clean.epub", '<a href="http://example.invalid/book">regular link</a>')
        write_epub(self.intake / "bad.epub", '<script>/* harmless fixture text */</script>')
        write_epub(nested / "bad.epub", '<nav><a href="#missing">chapter</a></nav>',
                   {"positive.xml": b"<metadata/>"})
        write_epub(nested / "nav.epub", '<nav><a href="#missing">chapter</a></nav>')
        write_epub(nested / "ocr.epub", "<p>text \ufffd\ufffd\ufffd</p>")
        write_epub(nested / "manifest.epub", additional={
            "broken.opf": b'<package><manifest><item href="absent.xhtml" media-type="application/xhtml+xml"/></manifest></package>',
        })
        (self.intake / "alias.epub").symlink_to(self.intake / "bad.epub")
        (self.intake / "linked_dir").symlink_to(nested, target_is_directory=True)
        self.quarantine.mkdir()
        old = self.quarantine / "bad.epub"
        old.write_bytes(b"Existing file")
        self.repair.mkdir()
        (self.repair / "excluded.epub").write_bytes(b"Excluded output")
        code, preview, _ = self.cli("--report-only")
        self.assertEqual(code, 1)
        self.assertFalse(self.queue.exists())
        top_code, top, _ = self.cli("--report-only", "--no-recursive", "--folder", self.intake)
        self.assertEqual(top_code, 1)
        self.assertEqual([row["path"] for row in top], ["bad.epub", "clean.epub"])
        selection_code, explicit, _ = self.cli("--report-only", "--folder", self.intake,
                                               "alias.epub", "nested/ocr.epub", "linked_dir/ocr.epub", "clean.epub")
        self.assertEqual(selection_code, 1)
        self.assertEqual([row["path"] for row in explicit], ["nested/ocr.epub", "clean.epub"])
        code, records, stderr = self.cli()
        self.assertEqual(code, 1)
        self.assertEqual(len(records), 6)
        self.assertEqual([(row["path"], row["action"], row["destination"]) for row in preview],
                         [(row["path"], row["action"], row["destination"]) for row in records])
        self.assertEqual(old.read_bytes(), b"Existing file")
        self.assertIn("Quarantine 2", stderr)
        self.assertFalse((nested / "bad.epub").exists())
        self.assertEqual(self.cli()[0], 1)
        with closing(sqlite3.connect(self.queue)) as connection:
            queued = connection.execute("SELECT source,sha256,status,repair_copy FROM repair_queue ORDER BY source").fetchall()
        self.assertEqual(len(queued), 3)
        self.assertEqual([row[2] for row in queued], ["verified_defect", "verified_defect", "needs_review"])
        for source, sha, _, copy in queued:
            self.assertTrue(Path(source).is_file())
            self.assertEqual(hashlib.sha256(Path(copy).read_bytes()).hexdigest(), sha)

    def test_queue_commit_failure_and_retry(self):
        source = self.intake / "review.epub"
        write_epub(source, "<p>text \ufffd\ufffd\ufffd</p>")
        expected = source.read_bytes()
        with patch.object(State, "commit", side_effect=sqlite3.OperationalError("injected queue failure")):
            code, rows, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(rows[0]["intended_action"], "stage_repair")
        self.assertEqual(source.read_bytes(), expected)
        self.assertEqual(Path(rows[0]["destination"]).read_bytes(), expected)
        with closing(sqlite3.connect(self.queue)) as connection:
            self.assertEqual(connection.execute("SELECT * FROM repair_queue").fetchall(), [])
        self.assertEqual(self.cli()[0], 1)
        self.assertEqual(self.cli()[0], 1)
        with closing(sqlite3.connect(self.queue)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM repair_queue").fetchone()[0], 1)

    def test_partial_write_occupied_temp_and_reintroduced_quarantine(self):
        source = self.intake / "active.epub"
        write_epub(source, "<script>/* harmless fixture text */</script>")
        expected = source.read_bytes()
        self.quarantine.mkdir()
        temp = self.quarantine / ".epub-triage-existing.part"
        temp.write_bytes(b"Occupied temp")
        real_copy = __import__("shutil").copyfileobj

        def partial_write(src, dest, length):
            dest.write(src.read(10))
            raise OSError("injected partial write")

        with patch("epub_triage.state.shutil.copyfileobj", side_effect=partial_write):
            self.assertEqual(self.cli()[0], 2)
        self.assertEqual(source.read_bytes(), expected)
        with patch("epub_triage.state.shutil.copyfileobj", real_copy):
            code, rows, _ = self.cli()
        self.assertEqual(code, 1)
        self.assertEqual(Path(rows[0]["destination"]).read_bytes(), expected)
        self.assertEqual(temp.read_bytes(), b"Occupied temp")
        self.assertFalse(source.exists())
        source.write_bytes(expected)
        self.assertEqual(self.cli()[0], 1)
        self.assertFalse(source.exists())

    def test_interrupted_after_source_removal(self):
        source = self.intake / "active.epub"
        write_epub(source, "<script>/* harmless fixture text */</script>")
        expected = source.read_bytes()
        with patch.object(State, "commit", side_effect=OSError("interrupted after source removal")):
            code, rows, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertFalse(source.exists())
        self.assertEqual(Path(rows[0]["destination"]).read_bytes(), expected)
        code, rows, _ = self.cli()
        self.assertEqual(code, 1)
        self.assertTrue(rows[0]["recovered"])
        self.assertEqual(self.cli()[0], 0)

    def test_preview_preserves_source_output_and_queue_metadata(self):
        source = self.intake / "book.epub"
        write_epub(source, '<nav><a href="#missing">chapter</a></nav>')
        _, result, _ = self.cli()
        paths = [source, self.intake, self.queue, self.repair, Path(result[0]["destination"])]
        for path in paths:
            timestamp = 1_000_000_000
            os.utime(path, ns=(timestamp, path.stat().st_mtime_ns))
        before = [path.stat() for path in paths]
        self.assertEqual(self.cli("--report-only")[0], 1)
        after = [path.stat() for path in paths]
        self.assertEqual([(x.st_atime_ns, x.st_mtime_ns, x.st_ctime_ns) for x in before],
                         [(x.st_atime_ns, x.st_mtime_ns, x.st_ctime_ns) for x in after])

    def test_preflight_and_worker_errors_preserve_source(self):
        source = self.intake / "book.epub"
        write_epub(source)
        original = source.read_bytes()
        with patch.object(TestBackend, "preflight", side_effect=RuntimeError("unavailable scanner")):
            code, rows, _ = self.cli()
        self.assertEqual((code, rows), (2, []))
        self.assertFalse(self.queue.exists())
        with patch.object(TestBackend, "inspect", side_effect=RuntimeError("worker killed")):
            code, rows, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(rows[0]["status"], "operational_error")
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(self.quarantine.exists())


if __name__ == "__main__":
    unittest.main()
