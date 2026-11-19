"""Review selection, durable decisions, and supervised candidate publication."""

from contextlib import ExitStack, contextmanager
from itertools import zip_longest
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import unicodedata
import uuid

from .repair import Repair, complete_findings, counter, safe
from .repair_state import PublicationCollision
from .review_cli import ReviewerUnavailable, ask, requested_model
from .review_work import OCR, SLICE, diagnostic_key, stable_hash
from .state import State, absolute_directory, digest, file_at, snap


SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_reviews (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES repair_queue(operation_id),
    book_sha256 TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(operation_id, book_sha256, occurrence)
);
CREATE TABLE IF NOT EXISTS agent_intentional (
    scope TEXT NOT NULL,
    occurrence TEXT NOT NULL,
    review_id TEXT NOT NULL REFERENCES agent_reviews(id),
    PRIMARY KEY(scope, occurrence)
);
CREATE TABLE IF NOT EXISTS agent_findings (
    id TEXT PRIMARY KEY,
    book TEXT NOT NULL,
    operation_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_review_events (
    sequence INTEGER PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES agent_reviews(id),
    event TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS agent_exports (
    review_id TEXT NOT NULL REFERENCES agent_reviews(id),
    path TEXT NOT NULL,
    PRIMARY KEY(review_id, path)
);
CREATE TABLE IF NOT EXISTS agent_batch (
    scope TEXT PRIMARY KEY,
    reviewer TEXT NOT NULL
);
"""


def candidate_root(config):
    queue = config["queue"]
    return queue.with_name("." + queue.name + "-review-candidates")


def key(diagnostic):
    return stable_hash(diagnostic_key(diagnostic))


def limit_text(value, maximum, minimum=1):
    return (isinstance(value, str) and minimum <= len(value) <= maximum
            and not any(character == "\x00" or 0xD800 <= ord(character) <= 0xDFFF for character in value))


def offset(value):
    return type(value) is int and 0 <= value <= 192 * 1024 * 1024


def valid_edit(edit):
    return (isinstance(edit, dict) and set(edit) == {"member", "start", "before", "after"}
            and limit_text(edit["member"], 2048) and offset(edit["start"])
            and limit_text(edit["before"], 4096) and limit_text(edit["after"], 4096, 0)
            and edit["before"] != edit["after"])


def data_request(request):
    action = request.get("action")
    if action == "read":
        return (set(request) == {"action", "member", "start"} and
                limit_text(request["member"], 2048) and offset(request["start"]))
    if action == "index":
        return set(request) == {"action", "start"} and offset(request["start"])
    if action == "search":
        cursor = request.get("after", ["", 0])
        return (set(request) <= {"action", "query", "after"} and limit_text(request.get("query"), 256)
                and isinstance(cursor, list) and len(cursor) == 2 and limit_text(cursor[0], 2048, 0)
                and offset(cursor[1]))
    if action == "diagnostic":
        terms = request.get("terms")
        return (set(request) == {"action", "name", "terms"} and request.get("name") == "count_variants"
                and isinstance(terms, list) and 1 <= len(terms) <= 12
                and all(limit_text(term, 128) for term in terms))
    return False


def verification_problem(intake, reviewed, candidate, baseline_occurrences, candidate_occurrences, selected):
    # v2 compares every warning, including severity, diagnostic details and multiplicity.
    if not safe(candidate) or not complete_findings(candidate):
        return "Candidate security or quality coverage failed or requires quarantine"
    for label, baseline in (("intake", intake), ("latest", reviewed)):
        if counter(candidate) - counter(baseline):
            return f"Candidate introduces or reintroduces a finding relative to {label}"
    original = {record["occurrence"] for record in baseline_occurrences}
    changed = [record for record in candidate_occurrences if record["occurrence"] not in original]
    compatible = [record for record in changed if record["locator"] == selected["locator"]
                  and key(record["finding"]) == key(selected["finding"])]
    if len(compatible) > 1 or (len(changed) != len(compatible)):
        return "Candidate introduces or reintroduces an occurrence"
    return None


class BookReview:
    def __init__(self, config, options, backend, state, private, limits, validate, emit):
        self.config, self.options, self.backend, self.private = config, options, backend, private
        self.connection = state.connection
        self.connection.executescript(SCHEMA)
        self.repair = Repair(state, backend, options, limits, private, validate)
        self.store = self.repair.store
        self.limits, self.validate, self.emit = limits, validate, emit

    def entries(self, book=None, operation=None):
        eligible = {}
        root_identity = None
        root_path = self.config.get("folder")
        if root_path:
            try:
                with absolute_directory(root_path) as root_fd:
                    info = os.fstat(root_fd)
                    root_identity = f"{info.st_dev}:{info.st_ino}"
            except FileNotFoundError:
                pass
        for entry in self.store.entries():
            entry = dict(entry)
            if root_path and (str(root_path) != entry["root"]
                              or (root_identity and root_identity != entry["root_identity"])):
                continue
            if book is not None and book != entry["relative"]:
                continue
            source = (entry["root"], entry["root_identity"], entry["relative"])
            head = self.connection.execute(
                "SELECT action, sha256 FROM source_heads WHERE root = ? AND root_identity = ? AND relative = ?",
                source,
            ).fetchone()
            if head and (head["action"] != "stage_repair" or head["sha256"] != entry["sha256"]):
                continue
            entry["scope"] = stable_hash(source)
            eligible.setdefault(source, []).append(entry)
        for source, versions in eligible.items():
            quarantined = self.connection.execute(
                """SELECT 1 FROM operations WHERE root = ? AND root_identity = ? AND relative = ?
                AND action = 'quarantine' AND complete = 1 LIMIT 1""", source,
            ).fetchone()
            head_exists = self.connection.execute(
                "SELECT 1 FROM source_heads WHERE root = ? AND root_identity = ? AND relative = ?", source,
            ).fetchone()
            if len(versions) == 1 and (not quarantined or head_exists):
                if operation is None or operation == versions[0]["operation_id"]:
                    yield versions[0]
                continue
            # Pre-v3 queues have no scan head. The original can disambiguate old copies.
            root, recorded_identity, relative = source
            target = Path(root) / relative
            try:
                with absolute_directory(Path(root)) as root_fd:
                    info = os.fstat(root_fd)
                    if recorded_identity != f"{info.st_dev}:{info.st_ino}":
                        continue
                with absolute_directory(target.parent) as parent:
                    with file_at(parent, target.name, preserve_atime=True) as stream:
                        actual = digest(stream) if os.fstat(stream.fileno()).st_size <= self.limits["max_book_bytes"] else None
            except (OSError, ValueError):
                continue
            yield from (entry for entry in versions if entry["sha256"] == actual and (
                operation is None or operation == entry["operation_id"]
            ))

    def entry_for(self, record):
        for entry in self.entries(record["book"], record["operation_id"]):
            return entry
        raise ValueError("Reviewed book is no longer available in the verified queue")

    @contextmanager
    def snapshots(self, entry):
        operation = entry["operation_id"]
        latest = self.store.latest(operation)
        with tempfile.TemporaryDirectory(dir=self.private) as staging:
            staging = Path(staging)
            intake = staging / "intake.epub"
            with self.repair.input_bytes(entry) as source:
                sha256, _, oversized = snap(source, intake, self.limits["max_book_bytes"])
            if sha256 != entry["sha256"] or oversized:
                raise ValueError("Intake fails its recorded hash or configured limit")
            intake.chmod(0o400)
            selected = intake
            if latest:
                selected = staging / "latest.epub"
                with self.store.latest_bytes(latest) as source:
                    sha256, _, oversized = snap(source, selected, self.limits["max_book_bytes"])
                if sha256 != latest["sha256"] or oversized:
                    raise ValueError("Latest accepted repair fails its recorded hash or configured limit")
                selected.chmod(0o400)
            report = self.inspect(selected)
            if not safe(report) or not complete_findings(report):
                raise ValueError("Book is quarantined or inspection coverage is incomplete")
            gate = self.repair.behavior.assess(selected, sha256)
            if gate["effective"] != "release":
                raise ValueError("Current review edition requires behavioral " + gate["effective"]
                                 + f" ({sha256}, {gate['configuration_id']})")
            yield selected, sha256, report, intake, latest

    def inspect(self, path):
        return self.validate(self.backend.inspect_repair(path, self.limits))

    def data(self, path, request, candidate=None):
        return self.backend.review_data(path, self.limits, request, candidate)

    def occurrences(self, path, report):
        result = self.data(path, {"action": "occurrences", "issues": report["quality"]["findings"]})
        if not isinstance(result.get("occurrences"), list):
            raise ValueError("Offline occurrence attribution failed")
        return result["occurrences"]

    def rows(self, entry, sha256, path, report):
        for occurrence in self.occurrences(path, report):
            token = occurrence["occurrence"]
            identifier = stable_hash(["review-v1", entry["operation_id"], sha256, token])
            existing = self.connection.execute("SELECT data FROM agent_reviews WHERE id = ?", (identifier,)).fetchone()
            intentional = self.connection.execute(
                "SELECT review_id FROM agent_intentional WHERE scope = ? AND occurrence = ?",
                (entry["scope"], token),
            ).fetchone()
            with self.connection:
                self.connection.execute("INSERT OR IGNORE INTO agent_findings VALUES (?, ?, ?)",
                                        (identifier, entry["relative"], entry["operation_id"]))
            yield {"id": identifier, "book": entry["relative"], "operation_id": entry["operation_id"],
                   "scope": entry["scope"],
                   "book_sha256": sha256, **occurrence,
                   "status": "intentional" if intentional else "pending",
                   "intentional_review": intentional["review_id"] if intentional else None,
                   "existing": json.loads(existing["data"]) if existing else None}

    def load(self, identifier):
        row = self.connection.execute("SELECT data FROM agent_reviews WHERE id = ?", (identifier,)).fetchone()
        if row is None:
            raise ValueError("Unknown review ID")
        return json.loads(row["data"])

    def save(self, record, event, event_data):
        encoded = json.dumps(record, ensure_ascii=True)
        with self.connection:
            self.connection.execute(
                """INSERT INTO agent_reviews VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET data = excluded.data""",
                (record["id"], record["operation_id"], record["book_sha256"], record["occurrence"], encoded),
            )
            self.connection.execute("INSERT INTO agent_review_events (review_id, event, data) VALUES (?, ?, ?)",
                                    (record["id"], event, json.dumps(event_data)))

    def call_reviewer(self, reviewer, payload):
        return ask(reviewer, self.config, self.private, payload)

    def assessment(self, reviewer, record, selected):
        indexed = self.data(selected, {"action": "index", "start": 0})
        passage = None
        if record["start"] is not None:
            initial = record["start"]
            passage = self.data(selected, {"action": "read", "member": record["finding"]["member"],
                                           "start": initial})
            if "text" in passage:
                end = min(record["end"], initial + SLICE)
                passage.update(end=end, text=passage["text"][:end - initial])
        payload = {"book_sha256": record["book_sha256"], "finding": record["finding"],
                   "members": indexed.get("members", []), "next_member_index": indexed.get("next"),
                   "passage": passage, "history": []}
        seen = set()
        for _ in range(self.config["review_turn_limit"]):
            answer = self.call_reviewer(reviewer, payload)
            if answer.get("action") == "assess":
                outcome = answer.get("outcome")
                evidence = answer.get("evidence")
                if (outcome not in ("edit", "intentional", "uncertain", "investigate")
                        or not limit_text(answer.get("rationale"), 6000)
                        or not isinstance(evidence, list) or not 1 <= len(evidence) <= 20
                        or not all(limit_text(item, 2000) for item in evidence)
                        or set(answer) != ({"action", "outcome", "rationale", "evidence", "edit"}
                                            if outcome == "edit" else {"action", "outcome", "rationale", "evidence"})):
                    raise ReviewerUnavailable("Reviewer returned an invalid assessment")
                decision = {**answer, "reviewer": reviewer,
                            "requested_model": requested_model(reviewer, self.config) or "CLI default", "passage": passage,
                            "diagnostics": payload["history"]}
                if outcome == "edit":
                    edit = answer.get("edit")
                    if (not valid_edit(edit) or edit["member"] != record["finding"].get("member")
                            or (record["finding"]["code"] == OCR and record["locator"] is not None
                                and not (record["start"] <= edit["start"]
                                         and edit["start"] + len(edit["before"]) <= record["end"]))):
                        return self.unusable_edit(decision, "Proposed edit is outside the selected finding's exact text scope")
                    match = self.data(selected, {**edit, "action": "validate_edit"})
                    if not match.get("matched"):
                        return self.unusable_edit(decision, match.get("denied", "Reviewer did not cite an exact source span"))
                    decision["original_context"] = match["context"]
                    decision["proposal_id"] = self.proposal_id(record, decision)
                    decision["diff"] = {"member": edit["member"], "start": edit["start"],
                                        "removed": edit["before"], "added": edit["after"]}
                return decision
            signature = stable_hash(answer)
            if not data_request(answer):
                result = {"denied": "Request is outside the read, search, and diagnostic allowlist"}
            elif signature in seen:
                result = {"denied": "Repeated data request. Use the existing result"}
            else:
                result = self.data(selected, answer)
            seen.add(signature)
            payload["history"].append({"request": answer, "result": result})
        raise ReviewerUnavailable("Reviewer exhausted its bounded data-request turns")

    @staticmethod
    def unusable_edit(assessment, reason):
        assessment["outcome"] = "investigate"
        assessment["unusable_edit"] = assessment.pop("edit")
        assessment["proposal_problem"] = reason
        return assessment

    @staticmethod
    def proposal_id(record, assessment):
        return stable_hash(["proposal-v1", record["id"], record["book_sha256"],
                            assessment["reviewer"], assessment["edit"]])

    def enumerate(self, review=False):
        options = self.options
        if options.batch and options.limit and options.limit > self.config["review_batch_limit"]:
            raise ValueError("Requested limit exceeds review_batch_limit")
        limit = options.limit or self.config["review_batch_limit"]
        scope = str(self.config.get("folder", "*"))
        paused = False
        count = found = 0
        if options.batch:
            previous = self.connection.execute("SELECT reviewer FROM agent_batch WHERE scope = ?", (scope,)).fetchone()
            if previous and previous["reviewer"] != options.reviewer:
                raise ValueError(f"Resume the paused batch with reviewer {previous['reviewer']}")
            with self.connection:
                self.connection.execute("INSERT OR IGNORE INTO agent_batch VALUES (?, ?)", (scope, options.reviewer))
        book = options.book
        operation = None
        if options.finding:
            located = self.connection.execute("SELECT book, operation_id FROM agent_findings WHERE id = ?",
                                              (options.finding,)).fetchone()
            if located:
                if book and book != located["book"]:
                    raise ValueError("Finding ID belongs to a different book")
                book, operation = located["book"], located["operation_id"]
            elif book is None:
                raise ValueError("Unknown finding ID. Discover it with review-list or supply its book")
        entries = list(self.entries(book, operation))
        if book and len(entries) > 1:
            raise ValueError("Book path selects multiple queue roots. Use --folder to disambiguate")
        for entry in entries:
            try:
                with self.snapshots(entry) as (selected, sha256, report, _, _):
                    for row in self.rows(entry, sha256, selected, report):
                        if options.finding and row["id"] != options.finding:
                            continue
                        found += 1
                        record = row.pop("existing")
                        if review and options.batch and (record is not None or row["status"] == "intentional"):
                            continue
                        if not review or record is not None or row["status"] == "intentional":
                            self.emit({**(record or row), **({"status": "intentional",
                                      "intentional_review": row["intentional_review"]}
                                      if row["status"] == "intentional" else {})})
                            continue
                        if count >= limit and options.batch:
                            continue
                        try:
                            assessment = self.assessment(options.reviewer, row, selected)
                        except ReviewerUnavailable as error:
                            self.emit({**row, "status": "paused", "reason": str(error), "reviewer": options.reviewer})
                            paused = True
                            break
                        row.update(status="reviewed", assessments=[assessment], reviewed_validation=report)
                        self.save(row, "primary", assessment)
                        self.emit(row)
                        if options.interactive:
                            self.readable(row)
                            self.interactive(row)
                        count += 1
                        if options.batch and count >= limit:
                            break
            except (OSError, ValueError) as error:
                self.emit({"book": entry["relative"], "status": "ineligible", "reason": str(error)})
            if paused or (options.batch and count >= limit):
                break
        if options.batch and not paused:
            with self.connection:
                self.connection.execute("DELETE FROM agent_batch WHERE scope = ?", (scope,))
        if book and not entries:
            raise ValueError("Selected book has no current eligible repair queue entry")
        if options.finding and not found:
            raise ValueError("Selected finding is absent from the current eligible book version")
        return 2 if paused else 0

    def current(self, record, sha256, path, report):
        if sha256 != record["book_sha256"]:
            raise ValueError("Reviewed book hash changed. Obtain a fresh proposal")
        findings = self.occurrences(path, report)
        for row in findings:
            if row["occurrence"] == record["occurrence"]:
                return row, findings
        raise ValueError("Selected finding no longer applies. Obtain a fresh proposal")

    @staticmethod
    def readable(record):
        def visible(value):
            return "".join(
                character if not unicodedata.category(character).startswith("C") else
                character.encode("unicode_escape").decode("ascii")
                for character in value
            )

        def column(assessment, width):
            reviewer = assessment["reviewer"]
            model = assessment["requested_model"]
            lines = [f"{reviewer} ({model})", f"Assessment {assessment['outcome']}"]
            passage = assessment.get("passage")
            if passage and "text" in passage:
                lines.append(f"Original {passage['member']} at character {passage['start']}")
                lines.append(json.dumps(passage["text"], ensure_ascii=False))
            if diff := assessment.get("diff"):
                lines.extend([f"Proposal {assessment['proposal_id']}", f"Exact offset {diff['start']}",
                              "- " + json.dumps(diff["removed"], ensure_ascii=False),
                              "+ " + json.dumps(diff["added"], ensure_ascii=False)])
            if problem := assessment.get("proposal_problem"):
                lines.append(problem)
            lines.extend([assessment["rationale"], "Evidence", *assessment["evidence"]])
            return [line for value in lines for line in textwrap.wrap(
                visible(value), width, replace_whitespace=False, drop_whitespace=False
            )]

        assessments = record["assessments"]
        width = max(76, shutil.get_terminal_size((120, 24)).columns)
        print(f"Review {record['id']} of {visible(record['book'])}", file=sys.stderr)
        if len(assessments) == 2:
            width = (width - 3) // 2
            first, second = (column(item, width) for item in assessments)
            for left, right in zip_longest(first, second, fillvalue=""):
                print(f"{left:<{width}} | {right}", file=sys.stderr)
        else:
            print("\n".join(column(assessments[0], width)), file=sys.stderr)
        sys.stderr.flush()

    def second(self, record):
        if len(record["assessments"]) != 1 or record["status"] != "reviewed":
            raise ValueError("Second opinion requires an open primary review and is allowed once")
        entry = self.entry_for(record)
        reviewer = "claude" if record["assessments"][0]["reviewer"] == "codex" else "codex"
        with self.snapshots(entry) as (selected, sha256, report, _, _):
            self.current(record, sha256, selected, report)
            rival = self.assessment(reviewer, record, selected)
            record["assessments"].append(rival)
            self.save(record, "second", rival)
        self.emit(record)
        self.readable(record)
        if self.options.interactive:
            self.interactive(record)

    @staticmethod
    def export_record(record):
        return {"review_id": record["id"], "book": record["book"], "book_sha256": record["book_sha256"],
                "finding": record["finding"], "assessments": record["assessments"]}

    def export_bytes(self, record):
        return (json.dumps(self.export_record(record), ensure_ascii=True, indent=2) + "\n").encode("ascii")

    def export(self, record, path):
        with path.open("xb") as target:
            target.write(self.export_bytes(record))
            target.flush()
            os.fsync(target.fileno())
        with self.connection:
            self.connection.execute("INSERT OR IGNORE INTO agent_exports VALUES (?, ?)",
                                    (record["id"], str(path.resolve())))

    def approval(self, record, proposal, exported, *, check_implicit_export=False):
        if check_implicit_export and exported is None:
            paths = self.connection.execute("SELECT path FROM agent_exports WHERE review_id = ?",
                                            (record["id"],)).fetchall()
            if len(paths) == 1:
                exported = Path(paths[0]["path"])
            elif len(paths) > 1:
                raise ValueError("Choose the exported copy using --export")
        if exported:
            with exported.open("rb") as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if data != self.export_bytes(record):
                raise ValueError("Exported proposal content differs from the exact recorded proposal")
        for assessment in record["assessments"]:
            if assessment.get("proposal_id") == proposal and proposal is not None:
                edit = assessment["edit"]
                if (proposal != self.proposal_id(record, assessment)
                        or assessment["diff"] != {"member": edit["member"], "start": edit["start"],
                                                   "removed": edit["before"], "added": edit["after"]}):
                    raise ValueError("Proposal identity or displayed diff fails integrity check")
                return assessment
        raise ValueError("Choose the exact proposal ID displayed for this review")

    def recover_publication(self, record, proposal):
        prior = self.store.previous(record["operation_id"], proposal)
        if not prior:
            return False
        accepted = json.loads(prior["report"])
        if accepted.get("review_id") != record["id"]:
            raise ValueError("Publication journal differs from review ID")
        publication = self.connection.execute(
            """SELECT v.* FROM repair_versions v JOIN repair_attempts a USING(sequence)
            WHERE a.operation_id = ? AND a.revision = ? AND v.ready = 1""",
            (record["operation_id"], proposal),
        ).fetchone()
        if publication is None:
            return False
        with self.store.latest_bytes(publication) as stream:
            if digest(stream) != accepted["output_sha256"]:
                raise ValueError("Recovered publication differs from recorded SHA-256")
        record.update(status="published", publication=accepted, verification={
            key: accepted[key] for key in ("candidate_sha256", "candidate_validation", "actual_change",
                                           "remaining_warning", "intake_validation", "reviewed_validation")
        })
        self.save(record, "published", accepted)
        self.emit(record)
        return True

    def decision(self, record, decision, proposal=None, exported=None, *, interactive=False):
        if record["status"] not in {"reviewed", "approved"}:
            raise ValueError("This review already has a user decision")
        if decision != "approve" and (proposal or exported or record["status"] == "approved"):
            raise ValueError("Approval arguments or state require the recorded approval")
        if decision == "approve" and record["status"] == "approved" and record.get("approved_proposal") != proposal:
            raise ValueError("Select the previously approved proposal to resume verification")
        if decision == "approve" and record["status"] == "approved":
            self.approval(record, proposal, exported, check_implicit_export=not interactive)
            if self.recover_publication(record, proposal):
                return
        entry = self.entry_for(record)
        with self.snapshots(entry) as (selected, sha256, report, intake, latest):
            finding, baseline = self.current(record, sha256, selected, report)
            if decision == "intentional":
                if finding["start"] is None or finding["locator"] is None:
                    raise ValueError("This finding has no identifiable passage to mark intentional")
                with self.connection:
                    self.connection.execute("INSERT INTO agent_intentional VALUES (?, ?, ?)",
                                            (record["scope"], record["occurrence"], record["id"]))
                    record["status"] = "intentional"
                    self.save(record, "user_decision", {"decision": decision})
            elif decision == "approve":
                assessment = self.approval(record, proposal, exported, check_implicit_export=not interactive)
                if record["status"] != "approved":
                    record.update(status="approved", approved_proposal=proposal)
                    self.save(record, "user_decision", {"decision": "approve", "proposal_id": proposal,
                                                        "book_sha256": sha256, "diff": assessment["diff"]})
                self.apply(record, assessment, selected, report, intake, latest, finding, baseline)
            else:
                record["status"] = {"reject": "rejected", "defer": "deferred", "investigate": "investigate"}[decision]
                self.save(record, "user_decision", {"decision": decision})
        self.emit(record)

    def interactive(self, record):
        try:
            with ExitStack() as stack:
                terminal = sys.stdin if sys.stdin.isatty() else stack.enter_context(
                    open("/dev/tty", encoding="utf-8")
                )
                print("Decide with approve PROPOSAL_ID, reject, defer, intentional, investigate, or Enter to leave open.",
                      file=sys.stderr, flush=True)
                command = terminal.readline().split()
                if command:
                    if len(command) > 2 or command[0] not in {"approve", "reject", "defer", "intentional", "investigate"}:
                        raise ValueError("Invalid interactive decision")
                    self.decision(record, *command, interactive=True)
        except OSError as error:
            raise ValueError("Interactive decisions require a controlling terminal") from error

    def staged(self, proposal):
        return candidate_root(self.config) / (proposal + ".epub")

    def stage(self, candidate, proposal, sha256):
        target = self.staged(proposal)
        with absolute_directory(target.parent, create=True) as directory:
            temporary = ".review-" + uuid.uuid4().hex + ".part"
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                try:
                    with os.fdopen(fd, "wb") as out, candidate.open("rb") as src:
                        shutil.copyfileobj(src, out)
                        out.flush()
                        os.fchmod(out.fileno(), 0o400)
                        os.fsync(out.fileno())
                    try:
                        os.link(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
                    except FileExistsError:
                        pass
                finally:
                    os.unlink(temporary, dir_fd=directory)
            except FileExistsError as error:
                raise ValueError("Candidate staging collision") from error
            self.repair.state.verify_target(directory, target.name, sha256, preserve_atime=True)
            os.fsync(directory)
        return target

    def recheck_publication_source(self, record, latest):
        entry = self.entry_for(record)
        current = self.store.latest(record["operation_id"])
        if (current and current["sequence"]) != (latest and latest["sequence"]):
            raise ValueError("Latest accepted edition changed during candidate verification")
        with self.repair.input_bytes(entry) as intake:
            if (os.fstat(intake.fileno()).st_size > self.limits["max_book_bytes"]
                    or digest(intake) != entry["sha256"]):
                raise ValueError("Intake changed during candidate verification")
        if current:
            with self.store.latest_bytes(current) as source:
                if (os.fstat(source.fileno()).st_size > self.limits["max_book_bytes"]
                        or digest(source) != record["book_sha256"]):
                    raise ValueError("Reviewed edition changed during candidate verification")
        elif entry["sha256"] != record["book_sha256"]:
            raise ValueError("Reviewed intake changed during candidate verification")

    def apply(self, record, assessment, selected, report, intake, latest, finding, baseline,
              confirmation=None):
        proposal = assessment["proposal_id"]
        with tempfile.TemporaryDirectory(dir=self.private) as work:
            candidate = Path(work) / "candidate.epub"
            built = self.data(selected, {"action": "build", "edit": assessment["edit"]}, candidate)
            if not built.get("built"):
                self.block(record, built.get("rejected", "Offline candidate build failed"), built)
                return
            if any(built.get("edit", {}).get(key) != value for key, value in assessment["edit"].items()):
                self.block(record, "Offline candidate does not report the approved replacement", built)
                return
            candidate.chmod(0o400)
            candidate_hash = built["candidate_sha256"]
            with candidate.open("rb") as source:
                if digest(source) != candidate_hash or candidate_hash == record["book_sha256"]:
                    self.block(record, "Candidate bytes did not match the exact checked change", built)
                    return
            intake_report = report if selected == intake else self.inspect(intake)
            after = self.inspect(candidate)
            if not safe(intake_report) or not complete_findings(intake_report):
                self.block(record, "Intake baseline no longer has complete coverage", intake_report)
                return
            occurrences = self.occurrences(candidate, after) if safe(after) and complete_findings(after) else []
            problem = verification_problem(intake_report, report, after, baseline, occurrences, finding)
            if problem:
                self.block(record, problem, after)
                return
            remaining = [row for row in occurrences if key(row["finding"]) == key(finding["finding"])
                         and row["locator"] == finding["locator"]]
            if remaining and finding["finding"]["kind"] != "heuristic":
                self.block(record, "Verified defect persisted after the edit", after)
                return
            verified = {"candidate_sha256": candidate_hash, "candidate_validation": after, "actual_change": built["edit"],
                        "remaining_warning": remaining, "intake_validation": intake_report,
                        "reviewed_validation": report}
            with candidate.open("rb") as stream:
                if digest(stream) != candidate_hash:
                    self.block(record, "Candidate changed during verification", verified)
                    return
            if confirmation and (not remaining or candidate_hash != confirmation):
                self.block(record, "Reverified candidate differs from the exact candidate awaiting confirmation", verified)
                return
            gate = self.repair.behavior.assess(candidate, candidate_hash)
            verified["behavior"] = gate
            if gate["effective"] != "release":
                if gate["effective"] == "quarantine":
                    self.block(record, "Candidate behavioral gate requires quarantine", verified)
                else:
                    record.update(verification=verified)
                    self.save(record, "behavior_hold", verified)
                return
            if remaining and confirmation is None:
                verified["candidate"] = str(self.stage(candidate, proposal, candidate_hash))
                record.update(status="awaiting_publication", verification=verified)
                self.save(record, "warning_persisted", verified)
                return
            try:
                self.recheck_publication_source(record, latest)
            except (OSError, ValueError, RuntimeError) as error:
                self.block(record, str(error), verified)
                return
            accepted = {**after, **verified, "phase": "repair", "path": record["book"],
                        "decision": "accepted", "verification": "verified", "status": "accepted",
                        "action": "repair", "sha256": record["book_sha256"],
                        "output_sha256": candidate_hash, "previous_sha256": latest["sha256"] if latest else None,
                        "review_id": record["id"], "proposal_id": proposal,
                        "edits": [built["edit"]], "persistent_warning_confirmation": confirmation}
            try:
                prior = self.store.previous(record["operation_id"], proposal)
                if prior:
                    journal = json.loads(prior["report"])
                    if any(journal.get(field) != accepted.get(field) for field in (
                        "review_id", "sha256", "output_sha256", "previous_sha256", "persistent_warning_confirmation"
                    )):
                        self.block(record, "Pending publication journal differs from the current verified approval", verified)
                        return
                    recovery = self.store.recover(record["operation_id"], review_revision=proposal,
                                                  inspect=self.repair.inspect_recovery)
                    if recovery:
                        verified["behavior"] = recovery
                        if recovery["effective"] == "quarantine":
                            self.block(record, "Pending publication requires behavioral quarantine", verified)
                        else:
                            record.update(verification=verified)
                            self.save(record, "behavior_hold", verified)
                        return
                    if self.store.previous(record["operation_id"], proposal):
                        accepted = json.loads(self.store.previous(record["operation_id"], proposal)["report"])
                    else:
                        self.store.publish(record["operation_id"], proposal, accepted, candidate)
                else:
                    self.store.publish(record["operation_id"], proposal, accepted, candidate)
            except PublicationCollision as error:
                self.block(record, str(error), verified)
                return
            record.update(status="published", verification=verified, publication=accepted)
            self.save(record, "published", accepted)

    def block(self, record, reason, verification):
        record.update(status="blocked", reason=reason, verification=verification)
        self.save(record, "blocked", {"reason": reason, "verification": verification})

    def publish(self, proposal, decision, sha256):
        record = None
        for row in self.connection.execute("SELECT data FROM agent_reviews"):
            item = json.loads(row["data"])
            if item.get("approved_proposal") == proposal:
                record = item
                break
        if (not record or record["status"] not in {"awaiting_publication", "publication_confirmed"}
                or record.get("verification", {}).get("candidate_sha256") != sha256):
            raise ValueError("Separate publication decision must identify the verified pending candidate and its SHA-256")
        if decision == "decline":
            if record["status"] == "publication_confirmed":
                raise ValueError("Publication confirmation is already recorded")
            record["status"] = "publication_declined"
            self.save(record, "publication_declined", {"candidate_sha256": sha256})
        else:
            if record["status"] == "publication_confirmed" and self.recover_publication(record, proposal):
                return
            target = self.staged(proposal)
            with absolute_directory(target.parent) as directory:
                self.repair.state.verify_target(directory, target.name, sha256, preserve_atime=True)
            entry = self.entry_for(record)
            with self.snapshots(entry) as (selected, actual, report, intake, latest):
                finding, baseline = self.current(record, actual, selected, report)
                assessment = self.approval(record, proposal, None)
                if record["status"] != "publication_confirmed":
                    record["status"] = "publication_confirmed"
                    self.save(record, "publication_confirmed", {"candidate_sha256": sha256})
                self.apply(record, assessment, selected, report, intake, latest, finding, baseline, sha256)
        self.emit(record)

    def audit(self, record):
        events = [dict(row) for row in self.connection.execute(
            "SELECT sequence, event, data, created_at FROM agent_review_events WHERE review_id = ? ORDER BY sequence",
            (record["id"],),
        )]
        for event in events:
            event["data"] = json.loads(event["data"])
        self.emit({**record, "events": events})


def run_review(options, config, backend_class, limits, validate, emit):
    if "repaired_output" not in config:
        raise ValueError("Set repaired_output in the configuration to enable agent review")
    with ExitStack() as stack:
        private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="epub-review-", dir="/tmp")))
        parent = stack.enter_context(absolute_directory(config["queue"].parent))
        fcntl.flock(parent, fcntl.LOCK_EX)
        state = stack.enter_context(State(config, config.get("folder"), None, False, private))
        backend = backend_class(config, private)
        if options.command not in {"review-export", "review-audit"}:
            backend.preflight()
        service = BookReview(config, options, backend, state, private, limits, validate, emit)
        command = options.command
        if command in {"review", "review-list"}:
            return service.enumerate(command == "review")
        if command == "review-publish":
            service.publish(options.identifier, options.decision, options.candidate_sha256)
            return 0
        record = service.load(options.identifier)
        if command == "review-second":
            service.second(record)
        elif command == "review-export":
            service.export(record, options.export)
        elif command == "review-audit":
            service.audit(record)
        elif command == "review-decide":
            service.decision(record, options.decision, options.proposal, options.export)
        return 0
