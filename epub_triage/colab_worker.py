"""Unprivileged Colab supervisor. Receives fixed basenames and no trusted credentials."""

import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
from zipfile import ZipFile

from .backend import Backend, OfflineWorkerTimeout
from .behavior import Behavior, ReaderBackend
from .cli import DEFAULT_LIMITS, choose_action, validate_result
from .reader_worker import ENGINES
from .repair import RULE_REVISIONS, accept, complete_findings, edit_matches, revision_for, safe

MiB = 1024 * 1024
BOOK_LIMIT = DEFAULT_LIMITS["max_book_bytes"][0]
CANDIDATE_LIMIT = 200 * MiB
BUFFER_ALLOWANCE = 16 * MiB
STATIC_TIMEOUT_OPERATIONS = frozenset({"isolation", "ready", "inspect", "inspect-repair",
                                       "plan-repair", "review-data"})


def static_reply(action, *args):
    try:
        return action(*args)
    except OfflineWorkerTimeout as error:
        operation = error.operation if error.operation in STATIC_TIMEOUT_OPERATIONS else "unknown"
        return {"pending": "static_timeout", "operation": operation}


def limits_for(size, stage):
    # A worker uses either one sized tmpfs or one sized tmpfs and one bounded
    # writable candidate. Nothing in a stage runs concurrently.
    allowance = stage - size - CANDIDATE_LIMIT - BUFFER_ALLOWANCE
    if allowance < 64 * MiB:
        raise ValueError("Configured staging limit is too small for one isolated book.")
    limits = {name: pair[0] for name, pair in DEFAULT_LIMITS.items()}
    limits["max_expanded_bytes"] = min(limits["max_expanded_bytes"], allowance // 2)
    return limits, min(1024 * MiB, allowance)


def fixture(book, image=""):
    container = ('<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0">'
                 '<rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/>'
                 '</rootfiles></container>')
    package = ('<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="work">'
               '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="work">urn:probe</dc:identifier>'
               '<dc:title>Qualification control</dc:title><dc:language>en</dc:language>'
               '<meta property="dcterms:modified">2025-01-01T00:00:00Z</meta></metadata>'
               '<manifest><item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>'
               '<item id="first" href="first.xhtml" media-type="application/xhtml+xml"/>'
               '<item id="second" href="second.xhtml" media-type="application/xhtml+xml"/></manifest>'
               '<spine><itemref idref="first"/><itemref idref="second"/></spine></package>')
    template = ('<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops" '
                'xml:lang="en"><head><title>Control</title></head><body>{}</body></html>')
    with ZipFile(book, "w") as out:
        out.writestr("mimetype", "application/epub+zip")
        out.writestr("META-INF/container.xml", container)
        out.writestr("book.opf", package)
        out.writestr("nav.xhtml", template.format(
            '<nav epub:type="toc"><ol><li><a href="first.xhtml#start">First</a></li>'
            '<li><a href="second.xhtml#note">Second</a></li></ol></nav>'))
        out.writestr("first.xhtml", template.format(
            '<h1 id="start">First</h1><p>A quiet page <a epub:type="noteref" id="ref" '
            'href="second.xhtml#note">with a note</a>.</p>' + image))
        out.writestr("second.xhtml", template.format(
            '<h1>Second</h1><aside epub:type="footnote" id="note">'
            '<p>Quiet note <a href="first.xhtml#ref">return</a></p></aside>'))


def probes(config, home):
    markers = config["worker_marker_paths"]
    scanner = {}
    try:
        scanner = Backend(config, home).preflight()
        if set(scanner["host_marker_denials"]) != set(markers):
            raise RuntimeError("Missing inspector marker denials.")
        scanner["ready"] = True
    except (OSError, RuntimeError, ValueError) as error:
        scanner = {"ready": False, "reason": str(error)[:350]}
    try:
        reader = ReaderBackend(config, home)
    except (OSError, RuntimeError, ValueError) as error:
        reason = str(error)[:350]
        return {"scan": scanner, "engines": {engine: {"ready": False, "reason": reason} for engine in ENGINES},
                "behavior_ready": False}
    engines = {}
    with socket.socket() as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen(4)
        address = canary.getsockname()
        with socket.create_connection(address, timeout=2), canary.accept()[0]:
            pass
        canary.setblocking(False)
        baseline, control, file_control = home / "baseline.epub", home / "blocked.epub", home / "file.epub"
        fixture(baseline)
        fixture(control, f'<p><img src="http://127.0.0.1:{address[1]}/control" width="24" '
                         'height="24" alt="control" /></p>')
        fixture(file_control, f'<p><img src="{Path(markers["unrelated_book"]).as_uri()}" width="24" '
                              'height="24" alt="control" /></p>')
        limits, _ = limits_for(control.stat().st_size, 1024 * MiB)
        navigation = None
        for engine in ENGINES:
            try:
                health = reader.health(engine)
                clean = reader.run(engine, baseline, limits, {"max_steps": 30})
                result = reader.run(engine, control, limits, {"max_steps": 30})
                steps = [[step["kind"], step["member"], step["fragment"], step["status"]]
                         for step in clean["steps"]]
                files = reader.run(engine, file_control, limits, {"max_steps": 30})
                events = [{field: event[field] for field in ("action", "step", "member", "blocked")}
                          for event in result["events"] + files["events"] if event["attribution"] == "book"]
                if (health.get("ready") is not True or not clean["complete"] or
                        any(evt["attribution"] == "book" for evt in clean["events"]) or
                        not any(step[2] == "note" and step[3] == "completed" for step in steps) or
                        any(not evt["blocked"] or evt["member"] != "first.xhtml" for evt in events) or
                        {evt["action"] for evt in events} != {"outbound_request", "out_of_book_read"} or
                        (navigation is not None and steps != navigation)):
                    raise RuntimeError("Comparable navigation or attributed denial control failed.")
                navigation = steps
                engines[engine] = {**health, "navigation": steps, "blocked": events}
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                engines[engine] = {"ready": False, "reason": str(error)[:350]}
        try:
            connection, _ = canary.accept()
        except BlockingIOError:
            no_egress = True
        else:
            connection.close()
            no_egress = False
    identities = {value.get("identity", {}).get("renderer") for value in engines.values()}
    return {"scan": scanner, "engines": engines, "host_loopback_positive": True,
            "host_loopback_received_worker_connection": not no_egress,
            "behavior_ready": no_egress and len(identities) == len(ENGINES) and
            all(value["ready"] for value in engines.values())}


def repair(backend, gate, book, sha256, limits, profile, preview, candidate):
    intake = validate_result(backend.inspect_repair(book, limits))
    report = {"decision": "review", "profile": profile, "rule_revision": revision_for(profile, limits),
              "before_validation": intake, "edits": []}
    if (not safe(intake) or not complete_findings(intake)
            or not any(finding["kind"] == "verified" for finding in intake["quality"]["findings"])):
        return {**report, "reason": "Current intake does not establish a complete verified defect."}
    plan = backend.plan_repair(book, limits, profile)
    report["edits"] = [{**edit, "rule_version": RULE_REVISIONS[edit["rule"]]} for edit in plan["edits"]]
    if plan["review"] or not plan["edits"]:
        return {**report, "reason": "The repair plan needs review.", "review": plan["review"]}
    if any(sum(edit_matches(edit, issue) for issue in intake["quality"]["findings"]) != 1
           for edit in plan["edits"]):
        return {**report, "reason": "A planned edit did not identify one verified defect."}
    if preview:
        return {**report, "decision": "planned"}
    built = backend.plan_repair(book, limits, profile, candidate)
    if not built.get("built") or built.get("rejected") or built["edits"] != plan["edits"]:
        return {**report, "decision": "rejected", "reason": "Candidate build did not reproduce the plan."}
    candidate.chmod(0o400)
    output_hash = digest(candidate)
    if output_hash != built.get("candidate_sha256") or output_hash == sha256:
        return {**report, "decision": "rejected", "reason": "Candidate bytes failed transfer verification."}
    result = validate_result(backend.inspect_repair(candidate, limits))
    report["candidate_validation"] = result
    if digest(candidate) != output_hash:
        raise RuntimeError("Candidate changed during inspection.")
    if safe(result):
        disposition = gate.assess(candidate, output_hash)
        report["behavior"] = disposition
        if disposition["effective"] != "release":
            return {**report, "decision": "behavior-" + disposition["effective"]}
    problem, fixes = accept(intake, result, None, plan["edits"])
    if problem:
        return {**report, "reason": problem, "decision": "rejected"}
    return {**report, "decision": "verified_candidate", "output_sha256": output_hash,
            "edits": [{**edit, "rule_version": RULE_REVISIONS[edit["rule"]]} for edit in fixes]}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect(config, book, home, request):
    sha256 = digest(book)
    if sha256 != request["sha256"]:
        raise ValueError("Staged input digest differs from the requested SHA-256.")
    limits, scratch = limits_for(book.stat().st_size, request["stage_bytes"])
    config.update(inspection_tmp_bytes=scratch, reader_tmp_bytes=scratch)
    backend = Backend(config, home)
    health = backend.preflight()
    gate = None
    if request.get("behavior", True):
        gate = Behavior(SimpleNamespace(config=config, preview=True, connection=None), home, limits)
        gate.preflight()
    report = validate_result(backend.inspect(book, limits))
    action, status = choose_action(report)
    report.update(action=action, status=status, sha256=sha256,
                  daily_published_epoch=health["daily_published_epoch"],
                  behavior_configuration=gate.identifier if gate else None)
    if action != "quarantine" and gate is None:
        report.update(action="hold", status="behavior_pending", static_action=action)
    if action != "quarantine" and gate is not None:
        gate_result = gate.assess(book, sha256)
        report["behavior"] = gate_result
        disposition = gate_result["effective"]
        if disposition != "release":
            report.update(action=disposition, status="behavior_" + disposition)
        elif action == "stage_repair" and request["profile"]:
            report["repair"] = repair(backend, gate, book, sha256, limits, request["profile"],
                                      request["report_only"], book.parent / "candidate.epub")
    return report


def review_work(config, book, home, request):
    from .review import BookReview, key, verification_problem
    expected = request["sha256"]
    if digest(book) != expected:
        raise ValueError("Review source differs from approved bytes.")
    limits, scratch = limits_for(book.stat().st_size, request["stage_bytes"])
    config.update(inspection_tmp_bytes=scratch, reader_tmp_bytes=scratch)
    backend = Backend(config, home)
    backend.preflight()
    report = validate_result(backend.inspect_repair(book, limits))
    gate = Behavior(SimpleNamespace(config=config, preview=True, connection=None), home, limits)
    if (not safe(report) or not complete_findings(report) or not report["quality"]["findings"]
            or gate.assess(book, expected)["effective"] != "release"):
        raise ValueError("Review requires an eligible, behaviorally released source.")
    action = request["review_request"]
    kind = action["action"]
    if kind == "findings":
        return {"findings": backend.review_data(book, limits, {
            "action": "occurrences", "issues": report["quality"]["findings"]})["occurrences"]}
    if kind != "verify":
        return backend.review_data(book, limits, action)
    finding = action["finding"]
    edit = action["edit"]
    baseline = backend.review_data(book, limits, {"action": "occurrences",
                                   "issues": report["quality"]["findings"]})["occurrences"]
    if not any(item == finding for item in baseline):
        raise ValueError("Finding changed or is absent from current source.")
    candidate = book.parent / "candidate.epub"
    built = backend.review_data(book, limits, {"action": "build", "edit": edit}, candidate)
    if not built.get("built") or any(built.get("edit", {}).get(k) != v for k, v in edit.items()):
        return {"status": "blocked", "reason": "Candidate build did not reproduce the exact edit."}
    actual = digest(candidate)
    if actual != built.get("candidate_sha256") or actual == expected:
        return {"status": "blocked", "reason": "Candidate differs from the checked worker bytes."}
    candidate.chmod(0o400)
    after = validate_result(backend.inspect_repair(candidate, limits))
    occurrences = backend.review_data(candidate, limits, {"action": "occurrences",
                                      "issues": after["quality"]["findings"]})["occurrences"] if safe(after) else []
    problem = verification_problem(report, report, after, baseline, occurrences, finding)
    if problem or digest(candidate) != actual:
        return {"status": "blocked", "reason": problem or "Candidate changed during verification."}
    remaining = [row for row in occurrences if key(row["finding"]) == key(finding["finding"])
                 and row["locator"] == finding["locator"]]
    if remaining and finding["finding"]["kind"] != "heuristic":
        return {"status": "blocked", "reason": "Verified defect persisted after the edit."}
    behavior = gate.assess(candidate, actual)
    status = "behavior_" + behavior["effective"] if behavior["effective"] != "release" else (
        "awaiting_publication_decision" if remaining else "verified_candidate")
    return {"status": status, "candidate_sha256": actual, "remaining_warning": remaining,
            "candidate_validation": after, "behavior_configuration": behavior["configuration_id"]}


def main():
    job = Path(sys.argv[1])
    request = json.loads((job / "request.json").read_text())
    config = {key: Path(request[key]) for key in ("database", "epubcheck_jar")}
    if request.get("behavior_python_packages"):
        config["behavior_python_packages"] = Path(request["behavior_python_packages"])
    if os.geteuid() == 0 or (os.readlink("/proc/self/ns/net") == request["controller_namespace"]
                             or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise RuntimeError("Outer worker identity or network namespace check failed.")
    for marker in request["marker_paths"].values():
        try:
            with open(marker, "rb"):
                raise RuntimeError("Host path visible to supervisor or monitor process.")
        except FileNotFoundError:
            pass
    if Path("/etc/resolv.conf").exists():
        raise RuntimeError("Host resolver is visible to supervisor or monitor process.")
    config.update(refresh_signatures=False, worker_marker_paths=request["marker_paths"],
                  behavior_timeout=request.get("behavior_timeout", 60))
    with tempfile.TemporaryDirectory(prefix="checks-", dir=job) as stage:
        home = Path(stage)
        if request["operation"] == "setup":
            result = {**probes(config, home), "monitor_outer_boundary": {
                "uid": os.geteuid(), "distinct_network_namespace": True,
                "controller_loopback_positive": request["controller_loopback_positive"],
                "host_marker_denials": sorted(request["marker_paths"])}}
        elif request["operation"] == "inspect":
            result = static_reply(inspect, config, job / "intake.epub", home, request)
        elif request["operation"] == "review":
            result = static_reply(review_work, config, job / "intake.epub", home, request)
        else:
            raise ValueError("Unknown supervisor operation.")
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
