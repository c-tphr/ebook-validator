"""Offline worker. Only the supervisor decides whether to modify book state."""

import errno
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import subprocess
import sys

from .archive import BookError, inventory


# The standard harmless EICAR antivirus test string.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SCAN_SIZE = 200 * 1024 * 1024
BOOK = Path("/input/book.epub")


def mount_probe(host_network_namespace, book=BOOK):
    if os.readlink("/proc/self/ns/net") == host_network_namespace:
        raise RuntimeError("Network namespace is shared with the host")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Unexpected network interface in inspection environment")
    if not os.statvfs(book).f_flag & os.ST_RDONLY:
        raise RuntimeError("Input mount is writable")
    try:
        descriptor = os.open(book, os.O_WRONLY)
    except OSError as error:
        if error.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
            raise
    else:
        os.close(descriptor)
        raise RuntimeError("Opening worker input for write succeeded")
    if Path("/etc/resolv.conf").exists():
        raise RuntimeError("Host resolver configuration is visible")
    return {"offline": True, "read_only": True, "namespace": os.readlink("/proc/self/ns/net")}


def run_capture(command, limit=2 * 1024 * 1024):
    capture = Path("/tmp/tool.log")
    with capture.open("w+b") as output:
        result = subprocess.run(command, stdout=output, stderr=output, check=False)
        if output.tell() > limit:
            raise RuntimeError("Tool output limit exceeded")
        output.seek(0)
        return result.returncode, output.read().decode("utf-8", errors="replace")


def scan(paths):
    from .content import finding

    if not paths:
        return []
    command = [
        "/usr/bin/clamscan", "--database=/signatures", "--no-summary", "--stdout",
        "--scan-archive=no", "--alert-exceeds-max=yes", "--alert-encrypted=yes",
        f"--max-filesize={SCAN_SIZE}", f"--max-scansize={SCAN_SIZE}",
        f"--max-scantime=120000", "--max-recursion=24", "--max-files=10000",
        "--",
    ]
    code, output = run_capture(command + [str(path) for path in paths])
    if code not in (0, 1):
        raise RuntimeError(f"ClamAV exited {code}: {output[-500:]}")
    pending = {str(path): index for index, path in enumerate(paths)}
    verdicts = [None] * len(paths)
    detected = False
    for line in output.splitlines():
        if not line:
            continue
        path, separator, verdict = line.partition(": ")
        if not separator or path not in pending:
            raise RuntimeError("Unexpected ClamAV result or diagnostic: " + line[:200])
        index = pending.pop(path)
        if verdict == "OK" or (verdict == "Empty file" and paths[index].stat().st_size == 0):
            continue
        if not verdict.endswith(" FOUND") or len(verdict) <= 6:
            raise RuntimeError("Invalid ClamAV result: " + verdict[:200])
        detected = True
        signature = verdict[:-6]
        if signature.lower().startswith("heuristics."):
            verdicts[index] = finding("incomplete", "scanner_heuristic", signature[:200])
        else:
            verdicts[index] = finding("malware", "malware_signature", signature[:200])
    if pending or detected != (code == 1):
        raise RuntimeError("ClamAV did not return consistent per-object verdicts")
    return verdicts


def java_check(arguments):
    return run_capture(["/usr/bin/java", "-Xmx512m", "-Djava.io.tmpdir=/tmp",
                        "-Dfile.encoding=UTF-8", "-jar", "/validator/epubcheck.jar", *arguments])


def quality_check(book, content):
    report = Path("/tmp/conformance.json")
    code, output = java_check([str(book), "--json", str(report)])
    if code not in (0, 1) or not report.is_file() or report.stat().st_size > 4 * 1024 * 1024:
        raise RuntimeError(f"EPUBCheck did not produce a usable report (exit {code}): {output[-400:]}")
    data = json.loads(report.read_text())
    messages = data.get("messages")
    if not isinstance(messages, list):
        raise RuntimeError("Unrecognized EPUBCheck report")
    verified = 0
    omitted_locations = False
    for message in messages:
        severity = message["severity"].upper()
        if severity in {"ERROR", "FATAL", "WARNING"}:
            verified += 1
            kind = "heuristic" if severity == "WARNING" else "verified"
            locations = message.get("locations") or [{}]
            if content.occurrences and message.get("additionalLocations"):
                omitted_locations = True
            if not content.occurrences:
                locations = [{}]
            for location in locations:
                member = location.get("path")
                if member == str(book):
                    member = None
                elif member and member.startswith(str(book) + "/"):
                    member = member[len(str(book)) + 1:]
                anchor = [location.get("line"), location.get("column")]
                diagnostic = json.dumps([str(message["ID"]), severity, message["message"],
                                         location.get("context")], sort_keys=True)
                content.add(kind, str(message["ID"])[:100], f"{severity}: {message['message']}"[:400],
                            member, anchor if any(value is not None for value in anchor) else None, diagnostic)
        elif severity not in {"INFO", "USAGE", "SUPPRESSED"}:
            raise RuntimeError("Unrecognized EPUBCheck severity")
    if omitted_locations:
        content.add("heuristic", "findings_capped", "EPUBCheck omitted additional diagnostic locations", None)
    if code and not verified:
        raise RuntimeError("EPUBCheck failed without a conformance diagnostic")


def inspect(book, limits, scratch=Path("/tmp"), occurrences=False):
    from .content import Content, finding

    target = scratch / "members"
    target.mkdir()
    try:
        members = inventory(book, target, limits)
    except BookError as error:
        archive_scan = scan([book])[0]
        initial = [archive_scan] if archive_scan else []
        initial.append(finding(error.kind, error.code, str(error), error.member))
        return {"security": {"complete": False, "findings": initial},
                "quality": {"complete": False, "findings": [],
                            "incomplete_reason": "Archive inventory did not complete."}}
    # Generated numeric member names keep the full argument list small enough for Linux execve.
    archive_scan, *member_verdicts = scan([book, *members.values()])
    content = Content(members, occurrences)
    for name, verdict in zip(members, member_verdicts, strict=True):
        if verdict:
            content.add(verdict["kind"], verdict["code"], verdict["detail"], name)
    content.inspect()
    security = ([archive_scan] if archive_scan else []) + content.security
    complete = all(entry["kind"] != "incomplete" for entry in security)
    quality = {"complete": not security, "findings": content.quality}
    if security:
        quality["incomplete_reason"] = "EPUBCheck was skipped because security findings require quarantine."
    else:
        quality_check(book, content)
        if occurrences:
            from .repair_rules import findings
            for issue in findings(book, members, limits):
                content.add(issue["kind"], issue["code"], issue["detail"], issue.get("member"),
                            issue.get("location"))
    return {"security": {"complete": complete, "findings": security}, "quality": quality}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (SCAN_SIZE, SCAN_SIZE))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
    operation, host_namespace = sys.argv[1:3]
    evidence = mount_probe(host_namespace)
    if operation == "isolation":
        markers = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        for path in markers.values():
            try:
                with open(path, "rb"):
                    raise RuntimeError("Private host control is visible in inspection worker")
            except FileNotFoundError:
                pass
        result = {**evidence, "host_marker_denials": sorted(markers)}
    elif operation == "ready":
        clean = Path("/tmp/clean")
        control = Path("/tmp/control")
        clean.write_bytes(b"Offline inspection readiness control.\n")
        control.write_bytes(EICAR)
        safe, positive = scan([clean, control])
        if safe is not None or positive is None or positive["kind"] != "malware" or "eicar" not in positive["detail"].lower():
            raise RuntimeError("ClamAV readiness controls did not pass")
        code, output = java_check(["--version"])
        if code or "epubcheck" not in output.lower():
            raise RuntimeError(f"EPUBCheck readiness failed: {output[-400:]}")
        result = {"ready": True, **evidence}
    elif operation in {"inspect", "inspect-repair"}:
        result = inspect(BOOK, json.loads(sys.argv[3]), occurrences=operation == "inspect-repair")
        if operation == "inspect-repair" and len(json.dumps(result)) > 768 * 1024:
            from .content import finding
            result = {"security": {"complete": False, "findings": [
                finding("incomplete", "repair_report_limit", "Complete findings exceed the repair protocol limit")
            ]}, "quality": {"complete": False, "findings": []}}
    elif operation == "plan-repair":
        from .repair_rules import plan
        staging = Path("/tmp/candidate.epub") if sys.argv[5] == "build" else None
        result = plan(BOOK, json.loads(sys.argv[3]), sys.argv[4], Path("/tmp"), staging)
        if len(json.dumps(result)) > 768 * 1024:
            result = {"edits": [], "review": [{"reason": "Complete plan exceeds the repair protocol limit"}],
                      "built": False}
        if result["built"]:
            shutil.copyfile(staging, "/output.epub")
    elif operation == "review-data":
        from .review_work import run
        staging = Path("/tmp/review-output.epub") if sys.argv[4] == "build" else None
        try:
            result = run(BOOK, json.loads(sys.argv[3]), json.loads(Path("/request.json").read_text()),
                         Path("/tmp"), staging)
        except BookError as error:
            result = {"rejected": str(error)}
        if result.get("built"):
            shutil.copyfile(staging, "/output.epub")
    else:
        raise RuntimeError("Unknown worker operation")
    print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
