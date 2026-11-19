"""Independent v3 workflow checks on synthetic books. No external provider keys."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from acceptance import model_fixtures
from acceptance.test_v2_review import ControlledWorker
from acceptance.v2_fixtures import write_book
from acceptance.behavior_double import FixtureReader

from epub_triage import cli, review_work

WORD = "Wor���d"


def book(path, paragraphs=None, signed=False, layout=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        base = write_book(Path(tmp) / "input.epub", signed=signed, layout=layout)
        with ZipFile(base) as original, ZipFile(path, "w") as output:
            body = "".join(
                f'<p id="line-{i}">{paragraph}</p>'
                for i, paragraph in enumerate(paragraphs or [WORD + " on the field."])
            )
            for item in original.infolist():
                data = original.read(item)
                if item.filename == "text.xhtml":
                    data = data.replace(b"<p>Original text.</p>", body.encode())
                output.writestr(item, data)
    return path


class Offline(ControlledWorker):
    fault = None

    def review_data(self, path, limits, request, candidate=None):
        if candidate is not None:
            type(self).candidates.add(str(candidate))
        with tempfile.TemporaryDirectory(dir=self.private) as tmp:
            return review_work.run(path, limits, request, Path(tmp), candidate)

    def inspect_repair(self, path, limits):
        report = super().inspect_repair(path, limits)
        if str(path) in self.candidates and type(self).fault == "regression":
            report["quality"]["findings"].append(
                dict(kind="verified", code="PKG-006", detail="Mimetype layout")
            )
        return report


class Scope(unittest.TestCase):
    def test_member_boundary_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selected = root / "chapter"
            selected.write_text(WORD + " Word Word")
            other = root / "another"
            other.write_text("secret marker")
            members = {"EPUB/a.xhtml": selected}
            for choice in [str(other), "../another", "EPUB/missing.xhtml"]:
                res = review_work.offline_scope(
                    members, dict(action="read", member=choice, start=0)
                )
                self.assertIn("denied", res)
            self.assertEqual(
                review_work.offline_scope(
                    members, dict(action="search", query="secret marker")
                )["matches"],
                [],
            )
            self.assertEqual(
                review_work.offline_scope(
                    members, dict(action="diagnostic", terms=["Word", WORD])
                )["counts"],
                {"Word": 2, WORD: 1},
            )
            for choice in ["shell", "write", "publish", "approve"]:
                with self.assertRaises((ValueError, RuntimeError)):
                    review_work.offline_scope(members, dict(action=choice))
            self.assertEqual(selected.read_text(), WORD + " Word Word")
            self.assertEqual(other.read_text(), "secret marker")

    def test_occurrence_survives_unrelated_edit_without_moving_to_a_twin(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "source"
            members = {"a.xhtml": p}
            issue = dict(
                member="a.xhtml",
                kind="heuristic",
                code="suspected_ocr_corruption",
                detail="OCR warning",
            )

            def occurrences(first, second, intro="Original intro"):
                p.write_text(
                    f'<html xmlns="http://www.w3.org/1999/xhtml"><body><p>{intro}</p><p id="a">{first}</p><p id="b">{second}</p></body></html>'
                )
                return [
                    e["occurrence"] for e in review_work.occurrences([issue], members)
                ]

            x, y = occurrences(WORD, WORD)
            self.assertNotEqual(x, y)
            self.assertEqual(occurrences(WORD, WORD, "Different intro"), [x, y])
            self.assertEqual(occurrences("now clear", WORD), [y])
            changed, kept = occurrences(WORD + "?", WORD)
            self.assertNotEqual(changed, x)
            self.assertEqual(kept, y)


class Transport(unittest.TestCase):
    def test_native_tool_messages_cannot_pass_relay(self):
        from epub_triage.review_cli import messages_only, validate_wire

        for provider, field in [("codex", "input"), ("claude", "messages")]:
            body = {
                field: [{"role": "user", "content": "ordinary book text"}],
                "tools": [{"name": "file_reader"}],
                "tool_choice": "auto",
                "previous_response_id": "prior",
            }
            messages_only(body, provider)
            self.assertEqual(set(body), {field})
        for provider, reply in [
            ("codex", {"output": [{"type": "function_call", "name": "file_reader"}]}),
            ("claude", {"content": [{"type": "tool_use", "name": "file_reader"}]}),
        ]:
            with self.assertRaises(ValueError):
                validate_wire(json.dumps(reply).encode(), "application/json", provider)
        for provider, event in [
            (
                "codex",
                dict(type="response.output_item.added", item={"type": "function_call"}),
            ),
            (
                "claude",
                dict(type="content_block_start", content_block={"type": "tool_use"}),
            ),
        ]:
            with self.assertRaises(ValueError):
                validate_wire(
                    ("data: " + json.dumps(event) + "\n\n").encode(),
                    "text/event-stream",
                    provider,
                )


class Workflow(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.books = self.root / "books"
        self.queue = self.root / "queue.sqlite"
        self.out = self.root / "published"
        self.cfg = self.root / "conf.toml"
        config = dict(
            folder=self.books,
            quarantine=self.root / "quarantine",
            repair=self.root / "intake",
            queue=self.queue,
            repaired_output=self.out,
            database=self.root / "db",
            epubcheck_jar=self.root / "checker.jar",
        )
        self.cfg.write_text(
            "".join(f"{k}={json.dumps(str(v))}\n" for k, v in config.items())
            + "review_batch_limit=2\n"
        )
        self.requests = []
        self.scenario = "conflict"
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch("epub_triage.behavior.ReaderBackend", FixtureReader))
        self.patches.enter_context(patch.object(cli, "Backend", Offline))
        Offline.candidates.clear()
        Offline.fault = None

    def emulate(self, reviewer, config, private, payload):
        self.requests.append((reviewer, json.loads(json.dumps(payload))))
        scenario = self.scenario
        if callable(scenario):
            ans = scenario(reviewer, payload)
            if isinstance(ans, dict):
                return ans
            scenario = ans
        provider = {"codex": "openai", "claude": "anthropic"}[reviewer]
        text = "EPUB_TRIAGE_REVIEW_V1\n" + json.dumps(payload, ensure_ascii=False)
        req = (
            {"input": text}
            if provider == "openai"
            else {"messages": [{"role": "user", "content": text}]}
        )
        return json.loads(
            model_fixtures.fixture_response(provider, req, scenario=scenario)
        )

    def invoke(self, command, *arguments, expected=None, input_text=""):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
            stderr
        ), patch("sys.stdin", io.StringIO(input_text)):
            rc = cli.main([command, "--config", str(self.cfg), *map(str, arguments)])
        if expected is not None:
            self.assertIn(
                rc,
                expected if isinstance(expected, tuple) else (expected,),
                (stdout.getvalue(), stderr.getvalue()),
            )
        return (
            rc,
            [
                json.loads(line)
                for line in stdout.getvalue().splitlines()
                if line.startswith("{")
            ],
            stderr.getvalue(),
        )

    def prepare(self, name="book.epub", paragraphs=None, **kwargs):
        from epub_triage import review

        if not getattr(self, "mocked", False):
            self.patches.enter_context(patch.object(review, "ask", self.emulate))
            self.mocked = True
        path = book(self.books / name, paragraphs, **kwargs)
        self.invoke("scan", name, expected=1)
        return path

    def primary(self, name="book.epub", reviewer="codex", **kw):
        _, rows, _ = self.invoke(
            "review", name, "--reviewer", reviewer, expected=0, **kw
        )
        self.assertTrue(rows)
        return rows[0]

    def decide(self, record, index=0, **kw):
        proposal = record["assessments"][index]["proposal_id"]
        _, rows, _ = self.invoke(
            "review-decide",
            record["id"],
            "approve",
            "--proposal",
            proposal,
            expected=0,
            **kw,
        )
        return rows[-1]

    def test_both_reviewer_orders_and_user_choices(self):
        for n, (primary, choice) in enumerate(
            [("codex", 0), ("claude", 1), ("codex", "reject"), ("claude", "defer")]
        ):
            name = f"b{n}.epub"
            self.prepare(name)
            first = self.primary(name, primary)
            self.assertEqual(first["assessments"][0]["reviewer"], primary)
            self.assertIn(WORD, first["assessments"][0]["passage"]["text"])
            _, rows, _ = self.invoke("review-second", first["id"], expected=0)
            rival = rows[-1]
            a, b = rival["assessments"]
            self.assertNotEqual(a["diff"]["added"], b["diff"]["added"])
            self.assertEqual(a["diff"]["start"], b["diff"]["start"])
            self.assertEqual(a["diff"]["removed"], WORD)
            incoming = self.requests[-1][1]
            self.assertEqual(incoming["history"], [])
            for leaked in [a["proposal_id"], a["rationale"]]:
                self.assertNotIn(leaked, json.dumps(incoming))
            if isinstance(choice, int):
                result = self.decide(rival, choice)
                self.assertEqual(result["status"], "published", result)
                selected = rival["assessments"][choice]
                output = Path(result["publication"]["destination"])
                self.assertEqual(
                    hashlib.sha256(output.read_bytes()).hexdigest(),
                    result["publication"]["output_sha256"],
                )
                with ZipFile(output) as z:
                    self.assertIn(
                        selected["edit"]["after"] + " on the field.",
                        z.read("text.xhtml").decode(),
                    )
                _, rows, _ = self.invoke("review-audit", rival["id"], expected=0)
                events = rows[-1]["events"]
                self.assertTrue(
                    any(
                        e["event"] == "user_decision"
                        and e["data"]["proposal_id"] == selected["proposal_id"]
                        for e in events
                    )
                )
            else:
                _, rows, _ = self.invoke(
                    "review-decide", rival["id"], choice, expected=0
                )
                self.assertEqual(
                    rows[-1]["status"],
                    {"reject": "rejected", "defer": "deferred"}[choice],
                )
                self.invoke(
                    "review-decide",
                    rival["id"],
                    "approve",
                    "--proposal",
                    a["proposal_id"],
                    expected=2,
                )

    def test_export_and_stale_version(self):
        p = self.prepare(layout=True)
        first = self.primary()
        a = first["assessments"][0]
        exported = self.root / "choice.json"
        self.invoke("review-export", first["id"], exported, expected=0)
        saved = exported.read_bytes()
        document = json.loads(saved)
        document["assessments"][0]["diff"]["added"] = "tampered"
        exported.write_text(json.dumps(document))
        self.invoke(
            "review-decide",
            first["id"],
            "approve",
            "--proposal",
            a["proposal_id"],
            "--export",
            exported,
            expected=2,
        )
        self.invoke(
            "review-decide",
            first["id"],
            "approve",
            "--proposal",
            a["proposal_id"],
            expected=2,
        )
        self.assertFalse(list(self.out.glob("*.epub")))
        exported.write_bytes(saved)
        self.invoke("repair", expected=1)
        (version,) = self.out.glob("*.epub")
        with ZipFile(version) as z, ZipFile(p) as original:
            self.assertEqual(z.read("text.xhtml"), original.read("text.xhtml"))
        self.invoke(
            "review-decide",
            first["id"],
            "approve",
            "--proposal",
            a["proposal_id"],
            "--export",
            exported,
            expected=2,
        )
        newer = self.primary()
        self.assertNotEqual(newer["id"], first["id"])
        self.assertEqual(
            newer["book_sha256"], hashlib.sha256(version.read_bytes()).hexdigest()
        )
        fresh = self.root / "fresh.json"
        self.invoke("review-export", newer["id"], fresh, expected=0)
        _, rows, _ = self.invoke(
            "review-decide",
            newer["id"],
            "approve",
            "--proposal",
            newer["assessments"][0]["proposal_id"],
            "--export",
            fresh,
            expected=0,
        )
        self.assertEqual(rows[-1]["status"], "published")

    def partial_repair(self, name="book.epub"):
        original = "Wor" + "�" * 6 + "d"
        self.prepare(name, [original + " on the field."])

        def partial(reviewer, payload):
            passage = payload["passage"]
            return dict(
                action="assess",
                outcome="edit",
                rationale="Only part of this word is legible.",
                evidence=[passage["member"] + ": " + original],
                edit=dict(
                    member=passage["member"],
                    start=passage["start"] + passage["text"].index(original),
                    before=original,
                    after=WORD,
                ),
            )

        self.scenario = partial

    def test_persistent_warning_requires_separate_bound_choice(self):
        # The approved edit leaves three replacement glyphs in the very same word.
        for i, decision in enumerate(["publish", "decline", "tamper"]):
            name = f"p{i}.epub"
            self.partial_repair(name)
            rec = self.primary(name)
            result = self.decide(rec)
            self.assertEqual(result["status"], "awaiting_publication", result)
            proposal = rec["assessments"][0]["proposal_id"]
            v = result["verification"]
            staged = Path(v["candidate"])
            self.assertEqual(
                hashlib.sha256(staged.read_bytes()).hexdigest(), v["candidate_sha256"]
            )
            self.assertTrue(v["remaining_warning"])
            before = len(list(self.out.glob("*.epub")))
            self.invoke(
                "review-publish",
                proposal,
                "publish",
                "--candidate-sha256",
                "0" * 64,
                expected=2,
            )
            if decision == "tamper":
                staged.chmod(0o600)
                staged.write_bytes(b"other verified bytes do not match")
                self.invoke(
                    "review-publish",
                    proposal,
                    "publish",
                    "--candidate-sha256",
                    v["candidate_sha256"],
                    expected=2,
                )
                self.assertEqual(len(list(self.out.glob("*.epub"))), before)
                continue
            _, rows, _ = self.invoke(
                "review-publish",
                proposal,
                decision,
                "--candidate-sha256",
                v["candidate_sha256"],
                expected=0,
            )
            self.assertEqual(
                rows[-1]["status"],
                "published" if decision == "publish" else "publication_declined",
            )
            self.assertEqual(
                len(list(self.out.glob("*.epub"))), before + int(decision == "publish")
            )

    def test_publication_blocks_candidate_faults_and_signatures(self):
        for fault in ["new", "incomplete", "active", "signed"]:
            name = fault + ".epub"
            p = self.prepare(name, signed=fault == "signed")
            rec = self.primary(name)
            Offline.fault = fault if fault != "signed" else None
            result = self.decide(rec)
            Offline.fault = None
            self.assertEqual(result["status"], "blocked", (fault, result))
            self.assertFalse(list(self.out.glob("*.epub")))
            self.assertEqual(p.read_bytes(), (self.root / "intake" / name).read_bytes())

    def test_batch_limit_pause_and_resume(self):
        from epub_triage.review_cli import ReviewerUnavailable

        for n in "abcd":
            self.prepare(n + ".epub")
        self.invoke("repair", expected=1)
        _, rows, _ = self.invoke("review-list", expected=0)
        self.assertFalse(self.requests)
        self.assertEqual(len(rows), 4)
        target = rows[-1]
        self.invoke(
            "review", "--finding", target["id"], "--reviewer", "claude", expected=0
        )
        self.assertEqual(len(self.requests), 1)
        seen = []

        def limited(reviewer, payload):
            if len(seen) == 1:
                raise ReviewerUnavailable("fixture HTTP 429")
            seen.append(payload)
            return "uncertain"

        self.scenario = limited
        _, rows, _ = self.invoke(
            "review", "--batch", "--limit", "2", "--reviewer", "codex", expected=2
        )
        self.assertIn("paused", [r["status"] for r in rows])
        complete = [r["id"] for r in rows if r["status"] == "reviewed"]
        self.assertEqual(len(complete), 1)
        self.invoke("review", "--batch", "--reviewer", "claude", expected=2)
        self.scenario = "uncertain"
        previous = len(self.requests)
        self.invoke(
            "review", "--batch", "--limit", "1", "--reviewer", "codex", expected=0
        )
        self.assertEqual(len(self.requests) - previous, 1)
        _, rows, _ = self.invoke("review-list", expected=0)
        self.assertEqual(sum(r["status"] == "pending" for r in rows), 1)
        prior_count = len(self.requests)
        self.invoke("review", "--batch", "--reviewer", "codex", expected=0)
        self.assertEqual(len(self.requests), prior_count + 1)

    def test_interactive_terminal_displays_and_applies_exact_proposal(self):
        import errno
        import os
        import pty
        import select
        import time

        self.prepare()
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os._exit(
                    cli.main(
                        [
                            "review",
                            "--config",
                            str(self.cfg),
                            "book.epub",
                            "--interactive",
                            "--reviewer",
                            "claude",
                        ]
                    )
                )
            except BaseException:
                os._exit(98)
        data = b""
        submitted = False
        status = None
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.15)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    data += chunk
                if not submitted and b"Decide with" in data:
                    displayed = next(
                        json.loads(l)
                        for l in data.decode().splitlines()
                        if l.startswith("{")
                    )
                    a = displayed["assessments"][0]
                    self.assertEqual(a["diff"]["removed"], WORD)
                    self.assertEqual(a["diff"]["added"], "Word")
                    os.write(fd, ("approve " + a["proposal_id"] + "\n").encode())
                    submitted = True
            child, status = os.waitpid(pid, os.WNOHANG)
            if not child:
                os.kill(pid, 9)
                _, status = os.waitpid(pid, 0)
        finally:
            os.close(fd)
        self.assertTrue(submitted, data[-1600:])
        rows = [
            json.loads(line)
            for line in data.decode().splitlines()
            if line.startswith("{")
        ]
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, data[-1600:])
        self.assertEqual(rows[-1]["status"], "published", data[-1600:])
        self.assertTrue(Path(rows[-1]["publication"]["destination"]).is_file())

    def test_scoped_read_search_diagnostic_and_latest_text(self):
        p = self.prepare(layout=True)
        # Introduce the v2-supported navigation case error before the fresh scan.
        with tempfile.TemporaryDirectory() as tmp:
            replacement = Path(tmp) / "case.epub"
            with ZipFile(p) as src, ZipFile(replacement, "w") as dst:
                for info in src.infolist():
                    raw = src.read(info)
                    if info.filename == "nav.xhtml":
                        raw = raw.replace(b"text.xhtml#start", b"Text.xhtml#start")
                    dst.writestr(info, raw)
            p.write_bytes(replacement.read_bytes())
        self.invoke("scan", p.name, expected=1)
        self.invoke("repair", "--profile", "broader", expected=1)
        self.prepare("other.epub", ["BOOK_TWO_ONLY " + WORD])

        def look(reviewer, payload):
            h = payload["history"]
            commands = [
                dict(action="read", member="nav.xhtml", start=0),
                dict(action="search", query="BOOK_TWO_ONLY"),
                dict(action="diagnostic", name="count_variants", terms=["Chapter one"]),
                dict(action="read", member="../other.epub", start=0),
                dict(action="shell", command="unavailable"),
            ]
            if len(h) < len(commands):
                return commands[len(h)]
            return "uncertain"

        self.scenario = look
        first = self.primary()
        history = first["assessments"][0]["diagnostics"]
        self.assertIn("text.xhtml#start", history[0]["result"]["text"])
        self.assertNotIn("Text.xhtml#start", history[0]["result"]["text"])
        self.assertFalse(history[1]["result"]["matches"])
        self.assertGreater(history[2]["result"]["counts"]["Chapter one"], 0)
        self.assertTrue(all("denied" in h["result"] for h in history[3:]))

    def test_intentional_decision_reopens_only_for_changed_occurrence(self):
        name = "twins.epub"
        self.prepare(name, [WORD, WORD, "Closing note."])
        _, rows, _ = self.invoke("review", name, "--reviewer", "claude", expected=0)
        self.assertEqual(len(rows), 2)
        a, b = rows
        self.invoke("review-decide", a["id"], "intentional", expected=0)
        _, listed, _ = self.invoke("review-list", name, expected=0)
        self.assertEqual([r["status"] for r in listed], ["intentional", "reviewed"])
        self.prepare(name, [WORD, WORD, "An unrelated closing note."])
        _, listed, _ = self.invoke("review-list", name, expected=0)
        self.assertEqual([r["status"] for r in listed], ["intentional", "pending"])
        self.assertNotEqual(a["book_sha256"], listed[0]["book_sha256"])
        self.invoke(
            "review-decide",
            b["id"],
            "approve",
            "--proposal",
            b["assessments"][0]["proposal_id"],
            expected=2,
        )
        self.prepare(name, [WORD + " changed", WORD, "An unrelated closing note."])
        _, listed, _ = self.invoke("review-list", name, expected=0)
        self.assertEqual([r["status"] for r in listed], ["pending", "pending"])

    def test_independent_occurrences_within_same_paragraph(self):
        name = "same-paragraph.epub"
        text = WORD + " on the field and " + WORD + " near the river."
        self.prepare(name, [text])
        _, items, _ = self.invoke("review-list", name, expected=0)
        items.sort(key=lambda row: row["start"])
        self.assertEqual(len(items), 2)
        first, second = items
        self.assertLessEqual(first["end"], second["start"])
        self.invoke(
            "review", name, "--finding", first["id"], "--reviewer", "codex", expected=0
        )
        self.invoke("review-decide", first["id"], "intentional", expected=0)
        _, pending, _ = self.invoke("review-list", name, expected=0)
        self.assertEqual({row["status"] for row in pending}, {"intentional", "pending"})
        _, assessed, _ = self.invoke(
            "review",
            name,
            "--finding",
            second["id"],
            "--reviewer",
            "claude",
            expected=0,
        )
        result = self.decide(assessed[0])
        self.assertEqual(result["status"], "published", result)
        _, surviving, _ = self.invoke("review-list", name, expected=0)
        self.assertEqual([row["status"] for row in surviving], ["intentional"])

    def test_new_damaged_word_cannot_use_persistent_warning_exception(self):
        self.prepare()

        def split_word(reviewer, payload):
            passage = payload["passage"]
            return dict(
                action="assess",
                outcome="edit",
                rationale="Uncertain transcription",
                evidence=[WORD],
                edit=dict(
                    member=passage["member"],
                    start=passage["start"] + passage["text"].index(WORD),
                    before=WORD,
                    after=WORD + " " + WORD,
                ),
            )

        self.scenario = split_word
        result = self.decide(self.primary())
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(list(self.out.glob("*.epub")))

    def test_changed_finding_reopens_and_untrusted_intake_is_ineligible(self):
        from epub_triage.review_work import OCR

        name = "check.epub"
        self.prepare(name)
        rec = self.primary(name)
        self.invoke("review-decide", rec["id"], "intentional", expected=0)
        original = Offline.inspect_repair

        def changed(backend, path, limits):
            report = original(backend, path, limits)
            for f in report["quality"]["findings"]:
                if f["code"] == OCR:
                    f["detail"] = "Different diagnostic for same passage"
            return report

        with patch.object(Offline, "inspect_repair", changed):
            _, rows, _ = self.invoke("review-list", name, expected=0)
            self.assertEqual(rows[0]["status"], "pending")
        (self.root / "intake" / name).write_bytes(b"changed intake")
        previous = len(self.requests)
        _, rows, _ = self.invoke("review", name, "--reviewer", "codex")
        self.assertTrue(any(r["status"] == "ineligible" for r in rows))
        self.assertEqual(previous, len(self.requests))

    def test_quarantine_overrides_historical_eligibility(self):
        name = "same.epub"
        p = self.prepare(name)
        rec = self.primary(name)
        with ZipFile(p, "a") as archive:
            archive.writestr("active.js", "/* benign active resource fixture */")
        self.invoke("scan", name, expected=1)
        before = len(self.requests)
        rc, rows, _ = self.invoke("review", name, "--reviewer", "claude")
        self.assertFalse(any(r.get("status") == "reviewed" for r in rows))
        self.assertEqual(before, len(self.requests))
        self.invoke(
            "review-decide",
            rec["id"],
            "approve",
            "--proposal",
            rec["assessments"][0]["proposal_id"],
            expected=2,
        )

    def test_mid_batch_process_exit_preserves_earlier_assessment(self):
        import multiprocessing, os

        for n in "abcd":
            self.prepare(n + ".epub")

        def die_after_one(reviewer, payload):
            if len(self.requests) > 1:
                os._exit(92)
            return "uncertain"

        self.scenario = die_after_one
        child = multiprocessing.get_context("fork").Process(
            target=self.invoke, args=("review", "--batch", "--reviewer", "claude")
        )
        child.start()
        child.join(10)
        self.assertEqual(child.exitcode, 92)
        _, pending, _ = self.invoke("review-list", expected=0)
        self.assertEqual(sum(r["status"] == "reviewed" for r in pending), 1)
        self.invoke("review", "--batch", "--reviewer", "codex", expected=2)
        self.scenario = "uncertain"
        self.invoke("review", "--batch", "--reviewer", "claude", expected=0)
        self.assertEqual(len(self.requests), 2)
        with contextlib.closing(sqlite3.connect(self.queue)) as c:
            counts = c.execute(
                "SELECT count(DISTINCT review_id), count(*) FROM agent_review_events WHERE event='primary'"
            ).fetchone()
        self.assertEqual(counts, (3, 3))

    def test_candidate_cannot_reintroduce_prior_v2_fix(self):
        self.prepare(layout=True)
        self.invoke("repair", expected=1)
        (prior,) = self.out.glob("*.epub")
        saved = prior.read_bytes()
        self.assertEqual(self.requests, [])
        rec = self.primary()
        Offline.fault = "regression"
        result = self.decide(rec)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(prior.read_bytes(), saved)
        self.assertEqual(list(self.out.glob("*.epub")), [prior])

    def test_recovery_after_crash_refuses_stale_pending_bytes(self):
        from epub_triage.repair_state import RepairState

        name = "journal.epub"
        self.prepare(name)
        first = self.primary(name)
        proposal = first["assessments"][0]["proposal_id"]
        with patch.object(
            RepairState,
            "finish",
            side_effect=RuntimeError("interrupted prior to object link"),
        ):
            self.invoke(
                "review-decide",
                first["id"],
                "approve",
                "--proposal",
                proposal,
                expected=2,
            )
        self.assertEqual(list(self.out.glob("*.epub")), [])
        (self.root / "intake" / name).write_bytes(b"externally replaced bytes")
        self.invoke("review-decide", first["id"], "approve", "--proposal", proposal)
        self.assertFalse(list(self.out.glob("*.epub")))

    def test_visible_publication_recovers_audit_once(self):
        from epub_triage.review import BookReview

        self.prepare()
        record = self.primary()
        proposal = record["assessments"][0]["proposal_id"]
        save = BookReview.save

        def interrupted(service, review, event, data):
            if event == "published":
                raise RuntimeError("interrupted after durable publication")
            return save(service, review, event, data)

        with patch.object(BookReview, "save", interrupted):
            self.invoke(
                "review-decide",
                record["id"],
                "approve",
                "--proposal",
                proposal,
                expected=2,
            )
        (output,) = self.out.glob("*.epub")
        original = output.stat()
        accepted = self.decide(record)
        self.assertEqual(accepted["status"], "published")
        self.assertEqual(output.stat().st_ino, original.st_ino)
        self.assertEqual(
            accepted["publication"]["output_sha256"],
            hashlib.sha256(output.read_bytes()).hexdigest(),
        )
        _, audit, _ = self.invoke("review-audit", record["id"], expected=0)
        self.assertEqual([e["event"] for e in audit[0]["events"]].count("published"), 1)

    def test_no_automatic_review_or_publication_from_selected_data(self):
        self.prepare()
        _, rows, _ = self.invoke("review-list", expected=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.requests, [])
        requests = [
            {"action": "read", "member": str(self.cfg), "start": 0},
            {"action": "write", "member": "text.xhtml", "text": "overwrite"},
            {"action": "approve", "proposal": "none"},
            {"action": "publish", "output": "another.epub"},
        ]

        def denied_actions(reviewer, payload):
            if len(payload["history"]) < len(requests):
                return requests[len(payload["history"])]
            return "uncertain"

        self.scenario = denied_actions
        p = self.books / "book.epub"
        original = p.read_bytes()
        row = self.primary()
        self.assertEqual(row["assessments"][0]["outcome"], "uncertain")
        self.assertTrue(
            all(
                "denied" in item["result"]
                for item in row["assessments"][0]["diagnostics"]
            )
        )
        self.assertEqual(p.read_bytes(), original)
        self.assertEqual((self.root / "intake" / p.name).read_bytes(), original)
        self.assertFalse(self.out.exists())

    def test_unfinished_security_never_calls_reviewer(self):
        self.prepare()

        def incomplete(backend, path, limits):
            return {
                "security": {
                    "complete": False,
                    "findings": [
                        {
                            "kind": "incomplete",
                            "code": "partial",
                            "detail": "controlled book limit",
                        }
                    ],
                },
                "quality": {"complete": False, "findings": []},
            }

        with patch.object(Offline, "inspect_repair", incomplete):
            _, rows, _ = self.invoke("review", "book.epub", "--reviewer", "claude")
        self.assertEqual(rows[0]["status"], "ineligible")
        self.assertEqual(self.requests, [])

    def test_retained_candidate_excluded_from_recursive_scan(self):
        # Keep SQLite alongside the library, a valid v1/v2 configuration.
        self.cfg.write_text(
            self.cfg.read_text().replace(
                str(self.queue), str(self.books / "queue.sqlite")
            )
        )
        self.partial_repair()
        result = self.decide(self.primary())
        self.assertEqual(result["status"], "awaiting_publication")
        candidate = Path(result["verification"]["candidate"])
        self.assertTrue(candidate.is_file())
        _, scans, _ = self.invoke("scan", "--report-only", expected=1)
        self.assertEqual([r["path"] for r in scans], ["book.epub"])
