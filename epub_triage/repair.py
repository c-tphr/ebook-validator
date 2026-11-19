"""Repair supervision, exact-candidate acceptance, and JSONL audit records."""

from collections import Counter
from contextlib import contextmanager
import errno
import hashlib
import json
from pathlib import Path

from .behavior import Behavior
from .repair_state import PublicationCollision, RepairState
from .state import SnapshotChanged, absolute_directory, digest, directory, file_at, snap


RULE_REVISIONS = {"M1": "1", "R1": "1", "D1": "1"}


def revision_for(profile, limits):
    rules = RULE_REVISIONS if profile == "broader" else {"M1": RULE_REVISIONS["M1"]}
    return hashlib.sha256(json.dumps([profile, rules, limits], sort_keys=True).encode()).hexdigest()


def counter(report):
    return Counter(json.dumps(item, sort_keys=True) for item in report["quality"]["findings"])


def safe(report):
    return (report["security"]["complete"] and not report["security"]["findings"]
            and report["quality"]["complete"])


def complete_findings(report):
    return not any(item["code"] == "findings_capped" for item in report["quality"]["findings"])


def edit_matches(edit, issue):
    if issue["kind"] != "verified" or issue["code"] not in edit["finding_codes"]:
        return False
    if edit["rule"] == "R1":
        return (issue.get("member") == edit["member"] and issue.get("location") == edit["locator"]
                and issue["detail"] == f"Missing navigation document {edit['evidence']['missing_target']}")
    if edit["rule"] == "D1":
        return (issue["code"] == "repair_identifier_pointer" and issue.get("member") == edit["member"]
                and issue.get("location") == edit["locator"])
    return issue["code"] == "repair_mimetype_layout" and issue.get("member") == "mimetype"


def accept(input_report, candidate_report, latest_report, edits):
    if not safe(candidate_report):
        return "Candidate security or quality coverage failed or requires quarantine", []
    if not complete_findings(candidate_report):
        return "Candidate finding list is incomplete", []
    candidate = counter(candidate_report)
    for label, baseline in (("intake", input_report), ("latest", latest_report)):
        if baseline and (candidate - counter(baseline)):
            return f"Candidate introduces a finding relative to {label}", []
    paired = []
    for edit in edits:
        before = [issue for issue in input_report["quality"]["findings"] if edit_matches(edit, issue)]
        after = [issue for issue in candidate_report["quality"]["findings"] if edit_matches(edit, issue)]
        if len(before) != 1 or after:
            return "A planned defect did not resolve with unique attribution", []
        paired.append({**edit, "before_findings": before, "after_findings": after,
                       "postcondition": "verified"})
    if not paired:
        return "Candidate made no targeted progress", []
    if latest_report and not any(
        any(edit_matches(edit, issue) for issue in latest_report["quality"]["findings"])
        for edit in edits
    ):
        return "Candidate made no targeted progress relative to the latest accepted version", []
    return None, paired


def edit_key(edit):
    return tuple(edit[key] for key in ("rule", "member", "locator", "after")) if edit["rule"] != "M1" else (
        "M1", "mimetype",
    )


class Repair:
    def __init__(self, state, backend, options, limits, private, validate, behavior=None):
        self.state = state
        self.behavior = behavior or Behavior(state, private, limits)
        self.store = RepairState(state, self.behavior)
        self.backend, self.options, self.limits = backend, options, limits
        self.private, self.validate = private, validate
        self.revision = revision_for(options.profile, limits)

    def select(self, scanned):
        if scanned is None:
            for row in self.store.entries():
                yield dict(row)
            return
        for record in scanned:
            entries = self.store.entries(record)
            found = False
            for entry in entries:
                found = True
                yield dict(entry)
            if not found and self.options.report_only:
                yield {"operation_id": None, "relative": record["path"], "sha256": record["sha256"],
                       "source": record["source"]}

    @contextmanager
    def input_bytes(self, entry):
        if entry["operation_id"] is None and self.options.report_only:
            relative = Path(entry["relative"])
            with directory(self.state.root_fd, relative.parts[:-1], preserve_atime=True) as parent:
                with file_at(parent, relative.name, preserve_atime=True) as source:
                    yield source
            return
        self.state.validate_target(entry, check_root=self.options.command == "scan")
        if entry["queued_sha256"] != entry["sha256"]:
            raise RuntimeError("Queued hash disagrees with completed scan state")
        target = Path(entry["repair_copy"])
        if target != Path(entry["target"]):
            raise RuntimeError("Queue intake path disagrees with completed scan state")
        with absolute_directory(target.parent, preserve_atime=self.options.report_only) as parent:
            with file_at(parent, target.name, preserve_atime=True) as source:
                yield source

    def record(self, entry):
        return {"phase": "repair", "path": entry["relative"], "source": entry["source"],
                "intake": entry.get("repair_copy"), "sha256": entry["sha256"],
                "profile": self.options.profile, "rule_revision": self.revision,
                "decision": "error", "status": "operational_error", "action": "error",
                "report_only": self.options.report_only, "verification": "unverified",
                "destination": None, "output_sha256": None, "latest": None, "edits": []}

    def inspect_recovery(self, book):
        if not safe(self.validate(self.backend.inspect_repair(book, self.limits))):
            raise RuntimeError("Pending candidate did not clear current static inspection")

    def process(self, entry, report):
        snapshot = self.private / "repair-snapshot.epub"
        candidate = self.private / "repair-candidate.epub"
        latest_path = self.private / "repair-latest.epub"
        try:
            self.behavior.preflight()
            self.process_paths(entry, report, snapshot, candidate, latest_path)
        finally:
            for path in (snapshot, candidate, latest_path):
                path.unlink(missing_ok=True)

    def process_paths(self, entry, report, snapshot, candidate, latest_path):
        operation = entry["operation_id"]
        def read_latest():
            latest = self.store.latest(operation)
            if latest:
                report["latest"] = {"sha256": latest["sha256"], "path": latest["path"]}
                report["latest_findings"] = json.loads(latest["report"]).get("quality")
            return latest

        read_latest()

        def decide(decision, reason=None, remember=False):
            report.update(decision=decision, action="repair", status=decision)
            if reason:
                report["reason"] = reason
            if remember and not self.options.report_only:
                self.store.remember(operation, self.revision, report)

        try:
            with self.input_bytes(entry) as source:
                actual, _, oversized = snap(source, snapshot, self.limits["max_book_bytes"])
        except (OSError, ValueError, SnapshotChanged) as error:
            if isinstance(error, OSError) and error.errno not in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR}:
                raise
            return decide("hash-mismatch", f"Queued intake is unavailable or changed: {error}")
        if actual != entry["sha256"]:
            return decide("hash-mismatch", "Intake bytes differ from queued SHA-256")
        if oversized:
            return decide("review", "Intake exceeds configured book limit", True)
        snapshot.chmod(0o400)
        findings = json.loads(entry.get("findings") or "{}")
        input_report = None
        # A legacy queue record has no behavioral receipt from its initial
        # static inspection. Reestablish static clearance before rendering it.
        if not findings.get("behavior"):
            input_report = self.validate(self.backend.inspect_repair(snapshot, self.limits))
            report.update(input_report, before_validation=input_report)
            if not safe(input_report):
                return decide("review", "Current intake inspection did not establish eligibility", True)
        intake_behavior = self.behavior.assess(snapshot, actual)
        report["intake_behavior"] = intake_behavior
        if intake_behavior["effective"] != "release":
            return decide("behavior-" + intake_behavior["effective"], "Intake behavioral gate is closed")
        recovery = self.store.recover(operation, inspect=self.inspect_recovery)
        if recovery:
            report["behavior"] = recovery
            return decide("behavior-" + recovery["effective"], "Pending publication behavioral gate is closed")
        latest = read_latest()
        if latest:
            try:
                with self.store.latest_bytes(latest) as source:
                    sha256, _, oversized = snap(source, latest_path, self.limits["max_book_bytes"])
            except (OSError, ValueError, RuntimeError) as error:
                return decide("review", f"Latest accepted output is unavailable: {error}")
            if oversized or sha256 != latest["sha256"]:
                return decide("review", "Latest accepted output fails its recorded hash or configured limit")
            latest_path.chmod(0o400)

        previous = self.store.previous(operation, self.revision)
        if previous and not self.options.report_only:
            historical = json.loads((latest or previous)["report"])
            report["quality"] = historical.get("quality")
            report["security"] = historical.get("security")
            return decide("unchanged", "Input, profile and applicable rule revisions were already processed")

        input_report = input_report or self.validate(self.backend.inspect_repair(snapshot, self.limits))
        report.update(input_report, before_validation=input_report)
        if not safe(input_report):
            return decide("review", "Current intake inspection did not establish eligibility", True)
        if not complete_findings(input_report):
            return decide("review", "Intake finding list is incomplete", True)
        if not any(finding["kind"] == "verified" for finding in input_report["quality"]["findings"]):
            return decide("review", "No verified defect is available for automatic repair", True)

        plan = self.backend.plan_repair(snapshot, self.limits, self.options.profile)
        report["edits"] = [{**edit, "rule_version": RULE_REVISIONS[edit["rule"]]} for edit in plan["edits"]]
        if plan["review"]:
            report["review"] = plan["review"]
            return decide("review", "The entire book requires review before applying this plan", True)
        if not plan["edits"]:
            return decide("review", "No supported edit has unambiguous evidence", True)
        if any(sum(edit_matches(edit, issue) for issue in input_report["quality"]["findings"]) != 1
               for edit in plan["edits"]):
            return decide("review", "A planned edit cannot be attributed to one verified defect", True)
        if latest:
            earlier = json.loads(latest["report"])
            if earlier.get("review_id"):
                return decide("review", "Automatic intake-based repair cannot replace an accepted text review", True)
            if not set(map(edit_key, earlier["edits"])) <= set(map(edit_key, plan["edits"])):
                return decide("review", "The plan does not preserve all previously accepted fixes", True)
        if self.options.report_only:
            return decide("planned")

        built = self.backend.plan_repair(snapshot, self.limits, self.options.profile, candidate)
        if built.get("rejected") or not built.get("built") or built["edits"] != plan["edits"]:
            return decide("rejected", built.get("rejected", "Candidate build did not reproduce the plan"), True)
        candidate.chmod(0o400)
        with candidate.open("rb") as source:
            candidate_hash = digest(source)
        if candidate_hash != built.get("candidate_sha256"):
            return decide("rejected", "Transferred candidate does not match checked worker bytes", True)
        if candidate_hash == entry["sha256"]:
            return decide("rejected", "Candidate is byte-for-byte identical to the intake", True)
        latest_report = None
        if latest:
            latest_report = self.validate(self.backend.inspect_repair(latest_path, self.limits))
            report["latest_validation"] = latest_report
            if not safe(latest_report) or not complete_findings(latest_report):
                return decide("review", "Latest accepted output could not be compared under current checks", True)
        candidate_report = self.validate(self.backend.inspect_repair(candidate, self.limits))
        report["candidate_validation"] = candidate_report
        with candidate.open("rb") as source:
            if digest(source) != candidate_hash:
                raise RuntimeError("Candidate bytes changed during verification")
        if safe(candidate_report):
            gate = self.behavior.assess(candidate, candidate_hash)
            report["behavior"] = gate
            if gate["effective"] != "release":
                return decide("behavior-" + gate["effective"], "Candidate behavioral gate is closed")
        if latest and candidate_hash == latest["sha256"] and safe(candidate_report) and complete_findings(candidate_report):
            report.update(candidate_report, verification="verified")
            return decide("unchanged", "Candidate matches the latest accepted output bytes", True)
        reason, edits = accept(input_report, candidate_report, latest_report, plan["edits"])
        if reason:
            return decide("rejected", reason, True)
        accepted = {**report, **candidate_report, "verification": "verified",
                    "output_sha256": candidate_hash, "previous_sha256": latest["sha256"] if latest else None,
                    "latest_findings": candidate_report["quality"], "decision": "accepted",
                    "action": "repair", "status": "accepted",
                    "edits": [{**edit, "rule_version": RULE_REVISIONS[edit["rule"]]} for edit in edits]}
        try:
            self.store.publish(operation, self.revision, accepted, candidate)
        except PublicationCollision as error:
            return decide("rejected", str(error))
        report.update(accepted)
