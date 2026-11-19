"""Independent v4 acceptance through the CLI with controlled reader receipts."""

import contextlib
import hashlib
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from acceptance import test_v3_review as v3
from acceptance.v2_fixtures import write_book
from acceptance.v4_books import make_book


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReaderDouble:
    """Replace only the reader transport for deterministic failure and recovery."""

    def __init__(self, *args, **kwargs):
        pass

    def health(self, engine):
        h = self.harness
        h.probes.append(engine)
        if engine == h.down:
            raise RuntimeError("simulated monitor outage")
        return dict(
            ready=True,
            identity=dict(
                engine=engine,
                renderer=engine,
                version=h.versions.get(engine, "simulated-1"),
            ),
            monitor="renderer-callback+seccomp-v1",
        )

    def run(self, engine, book, limits, options, comparison=False):
        h = self.harness
        hashed = sha(Path(book))
        h.calls.append((engine, hashed, comparison))
        receipt = dict(
            complete=True,
            steps=[
                dict(
                    kind="reading_order",
                    member="text.xhtml",
                    fragment="",
                    status="completed",
                    pages=[1],
                )
            ],
            gaps=[],
            events=[],
            external_links_unactivated=0,
        )
        if h.scenario:
            h.scenario(engine, Path(book), comparison, receipt)
        return receipt


class GateTests(TestCase):
    def setUp(self):
        from epub_triage import behavior

        self.app = v3.Workflow()
        self.app.setUp()
        self.addCleanup(self.app.doCleanups)
        self.calls, self.probes = [], []
        self.down = self.scenario = None
        self.versions = {}
        self.app.patches.enter_context(
            patch.object(ReaderDouble, "harness", self, create=True)
        )
        self.app.patches.enter_context(
            patch.object(behavior, "ReaderBackend", ReaderDouble)
        )
        self.command = self.app.invoke

    def scan(self, name, *opts):
        rc, rows, err = self.command("scan", name, *opts)
        self.assertEqual(len(rows), 1, (rc, rows, err))
        return rows[0]

    def test_intake_preview_and_config_cache(self):
        p = make_book(self.app.books / "alpha.epub")
        key = sha(p)
        self.scan(p.name, "--report-only")
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.app.queue.exists())
        self.assertEqual(sha(p), key)
        first = self.scan(p.name)
        self.assertEqual(first["behavior"]["outcome"], "release", first)
        self.assertEqual(len(self.calls), 4)
        cached = self.scan(p.name)["behavior"]
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(cached["reused"])
        self.assertEqual(len(self.probes), 6)
        self.versions["qt5"] = "simulated-2"
        self.assertNotEqual(
            self.scan(p.name)["behavior"]["configuration_id"],
            cached["configuration_id"],
        )
        with self.app.cfg.open("a") as out:
            out.write("behavior_max_steps=17\n")
        self.scan(p.name)
        self.assertEqual(len(self.calls), 8)
        p = make_book(p, missing=True)
        self.assertNotEqual(sha(p), key)
        self.scan(p.name)
        self.assertEqual(len(self.calls), 10)

    def test_static_quarantine_is_investigation_only(self):
        from acceptance.v4_books import IMAGE

        p = make_book(self.app.books / "quarantined.epub", image=IMAGE)
        key = sha(p)
        result = self.scan(p.name)
        self.assertEqual(result["action"], "quarantine", result)
        self.assertEqual(self.calls, [])
        copy = Path(result["destination"])
        _, rows, err = self.command("behavior-investigate", copy.name)
        self.assertTrue(rows, err)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(sha(copy), key)
        self.assertFalse(p.exists())
        self.assertEqual(rows[-1]["behavior"]["outcome"], "release")

    def test_unavailable_monitor_leaves_pending_and_resumes(self):
        p = make_book(self.app.books / "pending.epub")
        self.down = "weasyprint"
        self.command("scan", p.name, expected=2)
        self.assertEqual(self.calls, [])
        self.assertTrue(p.exists())
        self.down = None
        self.assertEqual(self.scan(p.name)["behavior"]["outcome"], "release")
        self.assertEqual(len(self.calls), 2)

    def test_v2_publishes_the_tested_hash_and_detects_substitution(self):
        from epub_triage.repair_state import RepairState

        self.app.books.mkdir()
        p = write_book(self.app.books / "layout.epub", layout=True)
        parent_hash = sha(p)
        result = self.scan(p.name)
        self.assertEqual(result["action"], "stage_repair", result)
        self.assertEqual([r[1] for r in self.calls], [parent_hash] * 2)
        publish = RepairState.publish

        def replace_before_copy(store, operation, rev, report, candidate):
            candidate.chmod(0o600)
            candidate.write_bytes(b"changed after behavioral verification")
            return publish(store, operation, rev, report, candidate)

        with patch.object(RepairState, "publish", replace_before_copy):
            _, failed, _ = self.command("repair")
        self.assertFalse(list(self.app.out.glob("*.epub")), failed)
        self.assertEqual(sha(p), parent_hash)
        self.assertEqual(sha(self.app.root / "intake" / p.name), parent_hash)
        _, rows, err = self.command("repair")
        (out,) = self.app.out.glob("*.epub")
        tested = sha(out)
        self.assertNotEqual(tested, parent_hash)
        self.assertEqual(rows[-1]["output_sha256"], tested, err)
        self.assertEqual(
            {e for e, h, _ in self.calls if h == tested}, {"qt5", "weasyprint"}
        )

    def test_v3_exact_candidate_approval_and_persistent_warning(self):
        self.app.partial_repair()
        record = self.app.primary()
        self.assertFalse(list(self.app.out.glob("*.epub")))
        decision = self.app.decide(record)
        self.assertEqual(decision["status"], "awaiting_publication", decision)
        proposal = record["assessments"][0]["proposal_id"]
        staged = Path(decision["verification"]["candidate"])
        tested = sha(staged)
        self.assertFalse(list(self.app.out.glob("*.epub")))
        self.command(
            "review-publish",
            proposal,
            "publish",
            "--candidate-sha256",
            "0" * 64,
            expected=2,
        )
        self.assertFalse(list(self.app.out.glob("*.epub")))
        _, rows, _ = self.command(
            "review-publish", proposal, "publish", "--candidate-sha256", tested
        )
        self.assertEqual(rows[-1]["status"], "published", rows)
        (out,) = self.app.out.glob("*.epub")
        self.assertEqual(sha(out), tested)
        self.assertEqual(
            {e for e, h, _ in self.calls if h == tested}, {"qt5", "weasyprint"}
        )

    def test_book_trigger_precedes_other_reader_timeout_and_records_provenance(self):
        import subprocess

        for n, action in enumerate(
            ("outbound_request", "out_of_book_read", "external_launch")
        ):
            p = make_book(self.app.books / f"trigger{n}.epub", missing=bool(n))
            # Ensure each book has distinct bytes, so decisions cannot reuse a cache key.
            from zipfile import ZipFile

            with ZipFile(p, "a") as out:
                out.comment = str(n).encode()

            def fires(engine, book, comparison, r):
                if engine == "weasyprint":
                    raise subprocess.TimeoutExpired("reader", 1)
                r["events"].append(
                    dict(
                        action=action,
                        step=0,
                        blocked=True,
                        attribution="book",
                        evidence="renderer_resource_request",
                        event_id="synthetic-event",
                        diagnostic_url="https://canary.invalid/path?credential=secret-value",
                    )
                )

            self.scenario = fires
            row = self.scan(p.name)
            b = row["behavior"]
            self.assertEqual(
                (row["action"], b["outcome"]), ("quarantine", "quarantine")
            )
            self.assertFalse(p.exists())
            self.assertTrue(Path(row["destination"]).exists())
            self.assertNotIn("secret-value", json.dumps(b))
            self.assertEqual(b["engines"]["qt5"]["events"][0]["step"], 0)
            self.assertFalse(b["engines"]["weasyprint"]["complete"])
            self.command(
                "behavior-override",
                b["sha256"],
                b["configuration_id"],
                "--reason",
                "reviewed",
                expected=2,
            )

    def test_empty_and_divergent_receipts_cannot_release(self):
        for i, mode in enumerate(("empty", "gap", "mismatch")):
            self.versions["qt5"] = mode
            p = make_book(self.app.books / f"incomplete{i}.epub")

            def contradictory(engine, book, comparison, r):
                if engine == "weasyprint":
                    if mode == "empty":
                        r["steps"] = []
                    elif mode == "gap":
                        r["gaps"] = ["required chapter skipped"]
                    else:
                        r["steps"][0]["member"] = "different-chapter.xhtml"

            self.scenario = contradictory
            rc, rows, err = self.command("scan", p.name)
            self.assertNotEqual(rc, 0, (mode, rows, err))
            self.assertFalse(any(row.get("action") == "leave" for row in rows))

    def test_crash_timeout_skip_and_hash_bound_hold_override(self):
        import sqlite3
        import subprocess

        for mode in ("crash", "timeout", "skip"):
            self.versions["qt5"] = mode
            p = make_book(self.app.books / (mode + ".epub"))

            def incomplete(engine, book, comparison, r):
                if engine == "qt5":
                    if mode == "crash":
                        raise RuntimeError("simulated renderer crash")
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired("reader", 1)
                    r.update(complete=False, gaps=["required chapter skipped"])
                    r["steps"][0]["status"] = "skipped"

            self.scenario = incomplete
            row = self.scan(p.name)
            self.assertEqual(row["action"], "hold", row)
            b = row["behavior"]
            self.assertTrue(b["engines"]["qt5"]["gaps"])
        self.command(
            "behavior-override",
            b["sha256"],
            b["configuration_id"],
            "--reason",
            " ",
            expected=2,
        )
        self.command(
            "behavior-override",
            b["sha256"],
            b["configuration_id"],
            "--reason",
            "checked offline edition",
            expected=0,
        )
        allowed = self.scan(p.name)
        self.assertEqual(
            (
                allowed["behavior"]["outcome"],
                allowed["behavior"]["effective"],
                allowed["action"],
            ),
            ("hold", "release", "leave"),
        )
        self.versions["weasyprint"] = "different"
        self.assertEqual(self.scan(p.name)["action"], "hold")
        make_book(p, missing=True)
        self.assertEqual(self.scan(p.name)["action"], "hold")
        with contextlib.closing(sqlite3.connect(self.app.queue)) as db:
            n = db.execute("select count(*) from behavior_traces").fetchone()[0]
            self.assertGreater(n, 0)
            db.execute("update behavior_traces set expires_at=0")
            db.commit()
            self.command("behavior-expire", expected=0)
            self.assertEqual(
                db.execute("select count(*) from behavior_traces").fetchone()[0], 0
            )
            self.assertTrue(
                db.execute(
                    "select 1 from behavior_results where sha256=? and configuration_id=?",
                    (b["sha256"], b["configuration_id"]),
                ).fetchone()
            )
            self.assertTrue(
                db.execute(
                    "select 1 from behavior_overrides where sha256=? and configuration_id=?",
                    (b["sha256"], b["configuration_id"]),
                ).fetchone()
            )

    def test_candidate_quarantine_leaves_previous_edition_intact(self):
        self.app.prepare(layout=True)
        _, records, _ = self.command("repair")
        (older,) = self.app.out.glob("*.epub")
        before = sha(older)
        first = self.app.primary()

        def candidate_only(engine, path, comparison, r):
            if sha(path) != before and engine == "weasyprint":
                r["events"] = [
                    dict(
                        attribution="book",
                        action="outbound_request",
                        blocked=True,
                        step=0,
                        evidence="renderer_resource_request",
                        event_id="simulated",
                    )
                ]

        self.scenario = candidate_only
        decision = self.app.decide(first)
        self.assertEqual(decision["status"], "blocked")
        self.assertEqual(sha(older), before)
        self.assertEqual(list(self.app.out.glob("*.epub")), [older])

    def test_single_control_for_ambiguity_and_reader_background(self):
        for mode in ("background", "reader", "book", "unresolved", "different-step"):
            self.versions["qt5"] = mode
            p = make_book(self.app.books / (mode + ".epub"))

            def uncertain(engine, path, comparison, r):
                if engine != "qt5":
                    return
                event = dict(
                    action="outbound_request",
                    step=0,
                    phase="navigation",
                    initiator="resource-broker",
                    event_id="same-control",
                    blocked=True,
                    attribution="ambiguous",
                    evidence="observed_reader_syscall",
                )
                if mode == "background":
                    event.update(
                        attribution="reader",
                        evidence="trusted_reader_startup",
                        step=None,
                        phase="startup",
                    )
                if comparison:
                    if mode == "unresolved":
                        return
                    if mode == "book":
                        event.update(
                            attribution="book", evidence="authenticated_book_replay"
                        )
                    else:
                        event.update(
                            attribution="reader", evidence="trusted_reader_control"
                        )
                        if mode == "different-step":
                            event["step"] = 1
                r["events"] = [event, event.copy()]

            self.scenario = uncertain
            start = len(self.calls)
            result = self.scan(p.name)["behavior"]
            self.assertEqual(
                result["outcome"],
                {
                    "background": "release",
                    "reader": "release",
                    "book": "quarantine",
                    "unresolved": "hold",
                    "different-step": "hold",
                }[mode],
                (mode, result),
            )
            self.assertEqual(
                sum(comp for _, _, comp in self.calls[start:]),
                int(mode != "background"),
            )

    def test_monitor_loss_cannot_be_overridden_or_cached_as_quiet(self):
        from epub_triage.behavior import MonitorUnavailable

        p = make_book(self.app.books / "monitor-loss.epub")

        def disconnect(engine, path, comparison, r):
            if engine == "qt5":
                raise MonitorUnavailable("end marker missing")

        self.scenario = disconnect
        row = self.scan(p.name)
        self.assertNotEqual(row["action"], "leave")
        if "behavior" in row:
            result = row["behavior"]
            self.command(
                "behavior-override",
                result["sha256"],
                result["configuration_id"],
                "--reason",
                "read manually",
                expected=2,
            )
        self.scenario = None
        self.assertEqual(self.scan(p.name)["action"], "leave")

    def test_hold_override_does_not_supply_v3_publication_consent(self):
        self.app.partial_repair()
        parent = sha(self.app.books / "book.epub")
        record = self.app.primary()

        def hold_candidate(engine, path, comparison, r):
            if sha(path) != parent:
                r.update(complete=False, gaps=["unsupported destination"])

        self.scenario = hold_candidate
        result = self.app.decide(record)
        b = result["verification"]["behavior"]
        self.assertEqual((b["outcome"], b["effective"]), ("hold", "hold"))
        proposal = record["assessments"][0]["proposal_id"]
        self.command(
            "review-publish",
            proposal,
            "publish",
            "--candidate-sha256",
            b["sha256"],
            expected=2,
        )
        self.assertFalse(list(self.app.out.glob("*.epub")))
        self.command(
            "behavior-override",
            b["sha256"],
            b["configuration_id"],
            "--reason",
            "manually verified note",
            expected=0,
        )
        result = self.app.decide(record)
        self.assertEqual(result["status"], "awaiting_publication")
        self.assertFalse(list(self.app.out.glob("*.epub")))
        self.command(
            "review-publish",
            proposal,
            "publish",
            "--candidate-sha256",
            b["sha256"],
            expected=0,
        )
        (actual,) = self.app.out.glob("*.epub")
        self.assertEqual(sha(actual), b["sha256"])

    def test_existing_protected_directories_unchanged_by_preview(self):
        from acceptance.test_v2_review import tree

        p = write_book(self.app.books / "layout.epub", layout=True)
        self.scan(p.name)
        before = tree(self.app.root)
        self.scan(p.name, "--report-only")
        self.assertEqual(before, tree(self.app.root))

    def test_v2_pending_journal_rechecks_behavior_before_link(self):
        from epub_triage.repair_state import RepairState

        self.app.books.mkdir()
        p = write_book(self.app.books / "journal.epub", layout=True)
        parent = sha(p)
        self.scan(p.name)
        with patch.object(
            RepairState,
            "finish",
            side_effect=RuntimeError("simulated crash before link"),
        ):
            self.command("repair", expected=2)
        self.assertFalse(list(self.app.out.glob("*.epub")))
        self.versions["weasyprint"] = "changed-after-crash"

        def refuse(engine, path, comparison, r):
            if sha(path) != parent:
                r.update(complete=False, gaps=["new coverage gap"])

        self.scenario = refuse
        _, rows, _ = self.command("repair")
        self.assertFalse(list(self.app.out.glob("*.epub")), rows)
        self.assertEqual(sha(p), parent)
        self.scenario = None
        _, rows, _ = self.command("repair")
        (out,) = self.app.out.glob("*.epub")
        self.assertTrue(any(digest == sha(out) for _, digest, _ in self.calls))

    def test_independent_file_witness_resolves_only_matching_native_read(self):
        from epub_triage.reader_worker import file_target_fingerprint

        p = make_book(self.app.books / "local-witness.epub")

        def observed(engine, path, comparison, receipt):
            if engine != "qt5" or comparison:
                return
            common = dict(
                action="out_of_book_read",
                member="text.xhtml",
                phase="navigation",
                step=0,
                file_target_fingerprint=file_target_fingerprint("/outside/canary"),
                blocked=True,
            )
            receipt["events"] = [
                dict(
                    **common,
                    initiator="renderer_resource_callback",
                    evidence="renderer_resource_request",
                    attribution="book",
                    event_id="callback",
                ),
                dict(
                    **common,
                    initiator="openat",
                    evidence="observed_reader_syscall",
                    attribution="ambiguous",
                    event_id="open",
                    syscall_result="ENOENT",
                ),
                dict(
                    **{
                        **common,
                        "file_target_fingerprint": file_target_fingerprint(
                            "/outside/different"
                        ),
                    },
                    initiator="openat",
                    evidence="observed_reader_syscall",
                    attribution="ambiguous",
                    event_id="unrelated",
                    syscall_result="ENOENT",
                ),
            ]

        self.scenario = observed
        r = self.scan(p.name)["behavior"]
        self.assertEqual(r["outcome"], "quarantine")
        events = r["engines"]["qt5"]["events"]
        self.assertEqual(events[1]["attribution"], "book")
        self.assertEqual(events[1]["corroborated_by"], "callback")
        self.assertEqual(events[2]["attribution"], "ambiguous")
        self.assertEqual(sum(comparison for _, _, comparison in self.calls), 1)
