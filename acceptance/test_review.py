"""Independent acceptance checks, restricted to generated books in disposable directories.

Run from the repository root with unittest. No test backend is selectable in the CLI.
"""

import contextlib
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import subprocess
from unittest.mock import Mock
import unittest
from unittest.mock import patch

from acceptance.fixtures import book
from acceptance.behavior_double import FixtureReader

from epub_triage import cli
from epub_triage.backend import Backend, AGE_LIMIT
from epub_triage.archive import BookError, inventory
from epub_triage.content import Content, finding
from epub_triage.state import State


class FixtureBackend:
    """Exercise production inventory and policy; stand in for external executables."""

    def __init__(self, config, private):
        self.private = private

    def preflight(self):
        return {"daily_published_epoch": 1}

    def inspect(self, path, limits):
        with tempfile.TemporaryDirectory(dir=self.private) as tmp:
            try:
                members = inventory(path, Path(tmp), limits)
            except BookError as error:
                return {
                    "security": {
                        "complete": False,
                        "findings": [finding(error.kind, error.code, str(error))],
                    },
                    "quality": {"complete": False, "findings": []},
                }
            content = Content(members)
            content.inspect()
            if b"Positive fixture marker" in path.read_bytes():
                content.add(
                    "malware", "malware_signature", "controlled scanner match", "text.xhtml"
                )
            return {
                "security": {
                    "complete": not any(f["kind"] == "incomplete" for f in content.security),
                    "findings": content.security,
                },
                "quality": {"complete": True, "findings": content.quality},
            }


@patch("epub_triage.behavior.ReaderBackend", FixtureReader)
def run_cli(config, *args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(cli, "Backend", FixtureBackend), contextlib.redirect_stdout(
        stdout
    ), contextlib.redirect_stderr(stderr):
        rc = cli.main(["--config", str(config), *args])
    return rc, [json.loads(line) for line in stdout.getvalue().splitlines()], stderr.getvalue()


def tree(base):
    result = {}
    for path in base.rglob("*"):
        if path.is_symlink():
            result[path.relative_to(base)] = ("link", os.readlink(path))
        else:
            result[path.relative_to(base)] = (
                ("file", path.read_bytes()) if path.is_file() else ("dir",)
            )
    return result


class Review(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "books"
        self.root.mkdir()
        self.config = self.base / "config.toml"
        self.values = dict(
            folder=str(self.root),
            quarantine=str(self.root / "Q"),
            repair=str(self.root / "R"),
            queue=str(self.base / "state" / "queue.sqlite"),
            database=str(self.base / "db"),
            epubcheck_jar=str(self.base / "validator.jar"),
        )
        self.configure()

    def configure(self, **changes):
        self.values.update(changes)
        self.config.write_text("".join(f"{k} = {json.dumps(v)}\n" for k, v in self.values.items()))

    def run_cli(self, *args):
        return run_cli(self.config, *args)

    def rows(self):
        with contextlib.closing(sqlite3.connect(self.values["queue"])) as db:
            return db.execute(
                "select source, sha256, findings, status, repair_copy from repair_queue"
            ).fetchall()

    def test_decisions_and_preview(self):
        cases = dict(
            clean="leave",
            click="leave",
            script="quarantine",
            remote="quarantine",
            corrupt="quarantine",
            both="quarantine",
            unlisted="quarantine",
            unsafe="quarantine",
            nav="stage_repair",
            manifest="stage_repair",
            heuristic="stage_repair",
            match="quarantine",
        )
        from acceptance.fixtures import BODY

        with patch.dict(BODY, match="<p>Positive fixture marker</p>"):
            for case in cases:
                book(self.root / (case + ".epub"), case)
        before = tree(self.base)
        previews = []
        for args in [[], ["--folder", str(self.root)]]:
            rc, rows, err = self.run_cli("--report-only", *args)
            self.assertEqual(rc, 1, err)
            self.assertEqual(len(rows), len(cases))
            self.assertEqual(before, tree(self.base))
            previews.append([(r["path"], r["action"], r["destination"]) for r in rows])
        code, rows, err = self.run_cli()
        self.assertEqual(code, 1, err)
        self.assertIn("Books", err)
        actual = [(r["path"], r["action"], r["destination"]) for r in rows]
        self.assertEqual(previews, [actual, actual])
        for row in rows:
            case = Path(row["path"]).stem
            with self.subTest(case=case):
                self.assertEqual(row["action"], cases[case], row)
                original = self.root / row["path"]
                self.assertEqual(original.exists(), cases[case] != "quarantine")
                data = before[original.relative_to(self.base)][1]
                self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
                if row["destination"]:
                    self.assertEqual(Path(row["destination"]).read_bytes(), data)
                if case == "corrupt":
                    self.assertFalse(row["security"]["complete"])
                    self.assertIn(row["security"]["findings"][0]["kind"], {"unsafe", "incomplete"})
                expected = {
                    "match": "malware",
                    "both": "active",
                    "script": "active",
                    "remote": "remote",
                    "unlisted": "remote",
                    "unsafe": "unsafe",
                    "heuristic": "heuristic",
                    "nav": "verified",
                    "manifest": "verified",
                }
                if case in expected:
                    kinds = {f["kind"] for k in ("security", "quality") for f in row[k]["findings"]}
                    self.assertIn(expected[case], kinds)
                    self.assertEqual("malware" in kinds, case == "match")
        queue = self.rows()
        self.assertEqual({Path(r[0]).stem for r in queue}, {"nav", "manifest", "heuristic"})
        for src, sha, findings, status, copy in queue:
            self.assertEqual(hashlib.sha256(Path(copy).read_bytes()).hexdigest(), sha)
            self.assertEqual(Path(src).read_bytes(), Path(copy).read_bytes())
            self.assertTrue(json.loads(findings)["quality"]["findings"])
            self.assertEqual(status == "needs_review", Path(src).stem == "heuristic")

    def test_selection_and_roots(self):
        override = self.base / "override"
        book(override / "chosen.epub")
        for name in ["a.epub", "b.EPUB", "c.epub", "sub/d.epub", "Q/e.epub", "R/f.epub"]:
            book(self.root / name)
        (self.root / "link.epub").symlink_to(override / "chosen.epub")
        (self.root / "alias").symlink_to(override, target_is_directory=True)
        for args, names in [
            ([], ["a.epub", "b.EPUB", "c.epub", "sub/d.epub"]),
            (["--no-recursive"], ["a.epub", "b.EPUB", "c.epub"]),
            (["sub/d.epub", "a.epub"], ["sub/d.epub", "a.epub"]),
            (["--folder", str(override)], ["chosen.epub"]),
        ]:
            rc, rows, err = self.run_cli("--report-only", *args)
            self.assertEqual(rc, 0, err)
            self.assertCountEqual([r["path"] for r in rows], names)
        for symlink in ["alias/chosen.epub", "link.epub"]:
            for request in [[symlink], [symlink, "a.epub"]]:
                rc, rows, err = self.run_cli("--report-only", *request)
                self.assertEqual(rc, 0, err)
                self.assertEqual([r["path"] for r in rows], request[1:])
        for bad in ["../outside.epub", "Q/e.epub", "R/f.epub"]:
            self.assertEqual(self.run_cli("--report-only", bad)[0], 2, bad)
        del self.values["folder"]
        self.configure()
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual(self.run_cli("--report-only", "--folder", str(override))[0], 0)

    def test_preflight_refresh_and_failure(self):
        (self.base / "db").mkdir()
        book(self.root / "source.epub", "remote")
        now = int(time.time())
        stale = now - AGE_LIMIT - 1

        def control(which, *args, **kwargs):
            return {"offline": True, "read_only": True, "ready": which == "ready"}

        for stamps, update_code, rc, updates in [
            ([now], 0, 1, 0),
            ([stale, now], 0, 1, 1),
            ([stale, stale], 0, 2, 1),
            ([stale], 1, 2, 1),
        ]:
            with self.subTest(stamps=stamps, update=update_code):
                clean_state = tree(self.base)
                update = Mock(return_value=subprocess.CompletedProcess([], update_code, b"", b""))

                def invoke_tool(name, *args, **kwargs):
                    if name == "freshclam":
                        return update(*args)
                    return subprocess.run(
                        ["/usr/bin/" + name, *args], capture_output=True, check=False
                    )

                with patch("epub_triage.behavior.ReaderBackend", FixtureReader), patch.object(cli, "Backend", Backend), patch.object(
                    Backend, "invoke", side_effect=control
                ), patch.object(Backend, "copy_generation", side_effect=stamps), patch(
                    "epub_triage.backend.tool", side_effect=invoke_tool
                ), patch.object(
                    Backend,
                    "inspect",
                    return_value={
                        "security": {
                            "complete": True,
                            "findings": [finding("remote", "remote", "test")],
                        },
                        "quality": {"complete": True, "findings": []},
                    },
                ):
                    out, err = io.StringIO(), io.StringIO()
                    args = ["--config", str(self.config)] + (["--report-only"] if rc == 1 else [])
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(cli.main(args), rc, err.getvalue())
                self.assertEqual(update.call_count, updates)
                self.assertEqual(clean_state, tree(self.base))

    def test_process_death_after_quarantine_unlink(self):
        source = self.root / "x.epub"
        book(source, "remote")
        original = source.read_bytes()

        def stop_before_commit(*args):
            os._exit(86)

        def killpoint():
            with patch.object(State, "commit", stop_before_commit):
                run_cli(self.config)

        child = multiprocessing.get_context("fork").Process(target=killpoint)
        child.start()
        child.join(10)
        self.assertEqual(child.exitcode, 86)
        self.assertFalse(source.exists())
        self.assertEqual((self.root / "Q/x.epub").read_bytes(), original)
        before = tree(self.base)
        prc, preview, err = self.run_cli("--report-only")
        self.assertEqual(prc, 1, err)
        self.assertTrue(preview[0]["pending"])
        self.assertEqual(before, tree(self.base))
        rc, rows, err = self.run_cli()
        self.assertEqual(rc, 1, err)
        self.assertTrue(rows[0]["recovered"])
        self.assertEqual(Path(rows[0]["destination"]).read_bytes(), original)
        self.assertEqual(self.run_cli()[0], 0)

    def test_limit_versus_worker_failure(self):
        for name in ["a.epub", "b.epub"]:
            book(self.root / name)
        with patch.object(FixtureBackend, "inspect", side_effect=RuntimeError("lost worker")):
            rc, rows, err = self.run_cli()
        self.assertEqual(rc, 2)
        self.assertEqual([r["action"] for r in rows], ["error", "error"])
        self.assertFalse((self.root / "Q").exists())
        self.configure(max_member_bytes=32)
        rc, rows, err = self.run_cli("a.epub")
        self.assertEqual(rc, 1, err)
        self.assertEqual(rows[0]["security"]["findings"][0]["code"], "member_limit")
        self.assertFalse(rows[0]["security"]["complete"])
        self.assertTrue((self.root / "b.epub").is_file())

    def test_queue_failure_and_copy_interruption(self):
        for kind in ["manifest", "nav"]:
            book(self.root / (kind + ".epub"), kind)
        with patch.object(
            State, "commit", side_effect=sqlite3.OperationalError("queue write failure")
        ):
            rc, rows, _ = self.run_cli("nav.epub")
        self.assertEqual(rc, 2)
        self.assertEqual(self.rows(), [])
        self.assertEqual(
            (self.root / "R/nav.epub").read_bytes(), (self.root / "nav.epub").read_bytes()
        )
        self.assertEqual(self.run_cli("nav.epub")[0], 1)

        def interrupted(src, dst, *args):
            dst.write(src.read(21))
            raise OSError("copy interrupted")

        with patch("epub_triage.state.shutil.copyfileobj", interrupted):
            rc, _, _ = self.run_cli("manifest.epub")
        self.assertEqual(rc, 2)
        self.assertFalse((self.root / "R/manifest.epub").exists())
        self.assertEqual(len(self.rows()), 1)
        for _ in range(2):
            rc, _, err = self.run_cli()
            self.assertEqual(rc, 1, err)
            self.assertEqual(len(self.rows()), 2)
        for src, sha, _, _, target in self.rows():
            self.assertEqual(Path(src).read_bytes(), Path(target).read_bytes())
            self.assertEqual(sha, hashlib.sha256(Path(target).read_bytes()).hexdigest())

    def test_collision_processes_cross_filesystem_and_reintroduction(self):
        second_fs = Path(os.environ.get("EPUB_ACCEPTANCE_SECOND_FS", "/dev/shm"))
        if not second_fs.is_dir():
            self.skipTest("second filesystem unavailable")
        with tempfile.TemporaryDirectory(dir=second_fs) as other:
            if os.stat(other).st_dev == os.stat(self.base).st_dev:
                self.skipTest("same filesystem")
            dest = Path(other)
            self.configure(quarantine=other)
            for name in ["aa/book.epub", "bb/book.epub"]:
                book(self.root / name, "remote")
            book(self.root / "fix.epub", "nav")
            (dest / "aa").mkdir()
            (dest / "aa/book.epub").write_bytes(b"occupied")
            original = (self.root / "aa/book.epub").read_bytes()
            with multiprocessing.get_context("fork").Pool(2) as pool:
                results = pool.starmap(run_cli, [(self.config,), (self.config,)])
            self.assertEqual([r[0] for r in results], [1, 1], results)
            self.assertEqual((dest / "aa/book.epub").read_bytes(), b"occupied")
            self.assertEqual(len(self.rows()), 1)
            self.assertTrue((dest / "bb/book.epub").exists())
            self.assertFalse((self.root / "aa/book.epub").exists())
            (self.root / "aa/book.epub").write_bytes(original)
            rc, rows, err = self.run_cli("aa/book.epub")
            self.assertEqual(rc, 1, err)
            self.assertFalse((self.root / "aa/book.epub").exists())
            self.assertEqual(Path(rows[0]["destination"]).read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
