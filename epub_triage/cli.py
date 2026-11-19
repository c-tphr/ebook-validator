"""Select books, conduct preflight, and report and apply per-book decisions."""

import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import sys
import tempfile
import tomllib

from .backend import Backend
from .behavior import Behavior, COMMANDS as BEHAVIOR_COMMANDS, LIMITS as BEHAVIOR_LIMITS, run_command
from .repair import Repair
from .review import candidate_root, run_review
from .state import State, absolute_directory, directory, file_at, snap


DEFAULT_LIMITS = {
    "max_book_bytes": (128 * 1024 * 1024, 192 * 1024 * 1024),
    "max_member_bytes": (48 * 1024 * 1024, 128 * 1024 * 1024),
    "max_expanded_bytes": (256 * 1024 * 1024, 512 * 1024 * 1024),
    "max_entries": (4096, 8192),
}
TIMEOUTS = {"readiness_timeout": (180, 1800), "inspection_timeout": (300, 3600),
            "review_timeout": (120, 600)}
REVIEW_LIMITS = {"review_batch_limit": (10, 100), "review_turn_limit": (8, 16)}
REVIEW_PATHS = {"codex_executable", "claude_executable"}
REVIEW_MODELS = {"codex_model", "claude_model"}
REVIEW_COMMANDS = {"review", "review-list", "review-second", "review-decide", "review-export",
                   "review-publish", "review-audit"}
REQUIRED = {"quarantine", "repair", "queue", "database", "epubcheck_jar"}
OPTIONAL = {"folder", "freshclam_config", "repaired_output", "behavior_python_packages"}
ERRORS = (OSError, RuntimeError, ValueError, sqlite3.Error)


def parse_review(command, args):
    parser = argparse.ArgumentParser(prog=f"epub-triage {command}")
    parser.add_argument("--config", type=Path, default=Path.home() / ".config/epub-triage/config.toml")
    parser.add_argument("--folder", type=Path)
    parser.set_defaults(command=command, profile="mechanical", report_only=False,
                        book=None, finding=None, batch=False, interactive=False, limit=None)
    if command in {"review", "review-list"}:
        parser.add_argument("book", nargs="?")
        if command == "review":
            parser.add_argument("--finding")
            parser.add_argument("--reviewer", required=True, choices=("codex", "claude"))
            parser.add_argument("--batch", action="store_true")
            parser.add_argument("--limit", type=int)
            parser.add_argument("--interactive", action="store_true")
    else:
        parser.add_argument("identifier")
        if command == "review-second":
            parser.add_argument("--interactive", action="store_true")
        elif command == "review-export":
            parser.add_argument("export", type=Path)
        elif command == "review-decide":
            parser.add_argument("decision", choices=("approve", "reject", "defer", "intentional", "investigate"))
            parser.add_argument("--proposal")
            parser.add_argument("--export", type=Path)
        elif command == "review-publish":
            parser.add_argument("decision", choices=("publish", "decline"))
            parser.add_argument("--candidate-sha256", required=True)
    options = parser.parse_intermixed_args(args)
    if command == "review":
        if options.batch == bool(options.book or options.finding):
            parser.error("select a book, a finding, or --batch")
        if options.limit is not None and (not options.batch or options.limit < 1):
            parser.error("--limit requires --batch and a positive integer")
        if options.interactive and options.batch:
            parser.error("batch review is unattended")
    return options


def parse(argv):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in BEHAVIOR_COMMANDS:
        command = args.pop(0)
        parser = argparse.ArgumentParser(prog=f"epub-triage {command}")
        parser.set_defaults(command=command, report_only=False)
        parser.add_argument("--config", type=Path, default=Path.home() / ".config/epub-triage/config.toml")
        parser.add_argument("--folder", type=Path, help=argparse.SUPPRESS)
        if command == "behavior-investigate":
            parser.add_argument("--report-only", action="store_true")
            parser.add_argument("book")
        if command == "behavior-override":
            parser.add_argument("sha256")
            parser.add_argument("configuration_id")
            parser.add_argument("--reason", required=True)
        return parser.parse_intermixed_args(args)
    if args and args[0] in REVIEW_COMMANDS:
        return parse_review(args[0], args[1:])
    parser = argparse.ArgumentParser(
        description="Inspect EPUBs offline and report security and quality separately",
        epilog="Agent review commands: review, review-list, review-second, review-export, "
               "review-decide, review-publish, and review-audit. Behavioral commands: behavior-investigate, "
               "behavior-override, and behavior-expire. Run a command with --help for its options.",
    )
    parser.add_argument("--config", type=Path, default=Path.home() / ".config/epub-triage/config.toml")
    parser.add_argument("--folder", type=Path)
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--repair", action="store_true", help="repair eligible books from this scan")
    parser.add_argument("--profile", choices=("mechanical", "broader"), default="mechanical")
    parser.add_argument("files", nargs="*")
    command = args.pop(0) if args and args[0] in {"scan", "repair"} else "scan"
    options = parser.parse_intermixed_args(args)
    options.command = command
    if command == "repair" and (options.repair or options.files or options.no_recursive):
        parser.error("standalone repair processes the queue for the configured folder")
    return options


def configuration(path, override, standalone=False):
    path = path.absolute()
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    if missing := REQUIRED - config.keys():
        raise ValueError("Missing configuration keys " + ", ".join(sorted(missing)))
    if unknown := config.keys() - REQUIRED - OPTIONAL - DEFAULT_LIMITS.keys() - TIMEOUTS.keys() - REVIEW_LIMITS.keys() - REVIEW_PATHS - REVIEW_MODELS - BEHAVIOR_LIMITS.keys():
        raise ValueError("Unknown configuration keys " + ", ".join(sorted(unknown)))
    for key in REQUIRED | OPTIONAL | REVIEW_PATHS:
        if key not in config:
            continue
        if not isinstance(config[key], str) or not config[key]:
            raise ValueError(f"Configuration key {key} requires a nonempty path")
        config[key] = Path(os.path.abspath(path.parent / config[key]))
    for key in REVIEW_MODELS & config.keys():
        if not isinstance(config[key], str) or not 1 <= len(config[key]) <= 128 or any(
            not character.isascii() or not (character.isalnum() or character in "-_.:/") for character in config[key]
        ):
            raise ValueError(f"Configuration key {key} requires a valid model name")
    for key, (default, maximum) in {**DEFAULT_LIMITS, **TIMEOUTS, **REVIEW_LIMITS, **BEHAVIOR_LIMITS}.items():
        value = config.get(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"Configuration key {key} must be an integer between 1 and {maximum}")
        config[key] = value
    if override is not None:
        config["folder"] = Path(os.path.abspath(override))
    if "folder" not in config and not standalone:
        raise ValueError("Set folder in the configuration or supply --folder")
    root = config.get("folder")
    quarantine, repair, queue, database = (
        config[key] for key in ("quarantine", "repair", "queue", "database")
    )
    def overlap(first, second):
        return first.is_relative_to(second) or second.is_relative_to(first)

    if ((root and (root.is_relative_to(quarantine) or root.is_relative_to(repair) or overlap(database, root)))
            or overlap(quarantine, repair)
            or queue.suffix.lower() == ".epub"
            or queue.is_relative_to(quarantine) or queue.is_relative_to(repair)
            or overlap(database, quarantine) or overlap(database, repair)
            or queue.is_relative_to(database)):
        raise ValueError("Intake, quarantine, repair, queue and database paths have incompatible overlap")
    repaired = config.get("repaired_output")
    if repaired and ((root and root.is_relative_to(repaired)) or any(
        overlap(repaired, path) for path in (quarantine, repair, queue, database)
    )):
        raise ValueError("Repaired output has incompatible overlap with intake, quarantine, repair, queue or database")
    staging = candidate_root(config)
    if ((root and root.is_relative_to(staging))
            or any(overlap(staging, item) for item in (quarantine, repair, database))
            or (repaired and overlap(staging, repaired))):
        raise ValueError("Queue-derived review staging has incompatible overlap with configured directories")
    if packages := config.get("behavior_python_packages"):
        if any(overlap(packages, item) for item in (root, quarantine, repair, queue, database, repaired, staging)
               if item is not None):
            raise ValueError("Reader dependency path overlaps protected state")
    return config


def explicit_names(files, root, excluded):
    output = {}
    for value in files:
        relative = PurePosixPath(value)
        if (relative.is_absolute() or ".." in relative.parts or relative.suffix.lower() != ".epub"
                or any((root / relative).is_relative_to(item) for item in excluded)):
            raise ValueError(f"Explicit selection is outside the safe EPUB scope: {value!r}")
        output[relative.as_posix()] = None
    return output


def blocked_path(root_fd, relative, output_ids):
    parts = PurePosixPath(relative).parts
    with ExitStack() as ancestors:
        parent = root_fd
        for index, part in enumerate(parts):
            try:
                info = os.stat(part, dir_fd=parent, follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                return False
            if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) in output_ids:
                return True
            if index < len(parts) - 1:
                if not stat.S_ISDIR(info.st_mode):
                    return False
                parent = ancestors.enter_context(directory(parent, (part,)))
    return False


def collect(root_fd, root, excluded, output_ids, recursive, preserve_atime=False):
    exclusions = {path.relative_to(root).parts for path in excluded if path.is_relative_to(root)}
    root_info = os.fstat(root_fd)
    seen = {(root_info.st_dev, root_info.st_ino), *output_ids}

    def walk(fd, parts):
        with os.scandir(fd) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
        for entry in ordered:
            child = parts + (entry.name,)
            if child in exclusions or entry.is_symlink():
                continue
            if recursive and entry.is_dir(follow_symlinks=False):
                info = entry.stat(follow_symlinks=False)
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                with directory(fd, (entry.name,), preserve_atime=preserve_atime) as nested:
                    yield from walk(nested, child)
            elif entry.name.lower().endswith(".epub") and entry.is_file(follow_symlinks=False):
                yield "/".join(child)

    return sorted(walk(root_fd, ()))


def validate_result(result):
    if not isinstance(result, dict):
        raise RuntimeError("Worker evidence is not an object")
    kinds = {"security": {"incomplete", "unsafe", "active", "remote", "malware"},
             "quality": {"verified", "heuristic"}}
    for section, allowed in kinds.items():
        report = result.get(section)
        if (not isinstance(report, dict) or type(report.get("complete")) is not bool
                or not isinstance(report.get("findings"), list) or len(report["findings"]) > 105):
            raise RuntimeError(f"Invalid worker {section} evidence")
        for finding in report["findings"]:
            if (not isinstance(finding, dict)
                    or any(not isinstance(finding.get(key), str) or not finding[key]
                           for key in ("kind", "code", "detail"))
                    or finding["kind"] not in allowed
                    or ("member" in finding and not isinstance(finding["member"], str))):
                raise RuntimeError(f"Invalid worker {section} finding")
    if not result["security"]["complete"] and not result["security"]["findings"]:
        raise RuntimeError("Worker returned incomplete security evidence without a reason")
    if (result["security"]["complete"] and any(
        entry["kind"] in {"incomplete", "unsafe"} for entry in result["security"]["findings"]
    )):
        raise RuntimeError("Worker returned inconsistent security completeness")
    if not result["security"]["findings"] and not result["quality"]["complete"]:
        raise RuntimeError("Worker did not complete quality checks")
    return {key: result[key] for key in kinds}


def record_for(relative, root, preview):
    return {"path": relative, "source": str(root / relative), "sha256": None,
            "security": {"complete": False, "findings": []},
            "quality": {"complete": False, "findings": []},
            "action": "error", "destination": None, "status": "operational_error", "report_only": preview}


def choose_action(record):
    security, quality = record["security"]["findings"], record["quality"]["findings"]
    if security:
        return "quarantine", "quarantine"
    if quality:
        status = "verified_defect" if any(entry["kind"] == "verified" for entry in quality) else "needs_review"
        return "stage_repair", status
    return "leave", "clean"


def emit(record):
    print(json.dumps(record, ensure_ascii=True, separators=(",", ":")), flush=True)


def run(options, config):
    if options.command in BEHAVIOR_COMMANDS:
        return run_command(options, config, {key: config[key] for key in DEFAULT_LIMITS}, emit)
    if options.command in REVIEW_COMMANDS:
        if options.book is not None:
            names = explicit_names([options.book], config.get("folder", Path("/")), ())
            options.book = next(iter(names))
        limits = {key: config[key] for key in DEFAULT_LIMITS}
        return run_review(options, config, Backend, limits, validate_result, emit)
    root = config.get("folder")
    standalone = options.command == "repair"
    repair_requested = options.command == "repair" or options.repair
    if repair_requested and "repaired_output" not in config:
        raise ValueError("Set repaired_output in the configuration to enable repair")
    excluded = (candidate_root(config), *(
        config[key] for key in ("quarantine", "repair", "repaired_output") if key in config
    ))
    requested = explicit_names(options.files, root, excluded)
    counts = {"clean": 0, "quarantine": 0, "repair": 0, "hold": 0, "errors": 0}
    actions = {"leave": "clean", "quarantine": "quarantine", "stage_repair": "repair", "hold": "hold", "error": "errors"}
    with ExitStack() as stack:
        root_fd = None if standalone else stack.enter_context(
            absolute_directory(root, preserve_atime=options.report_only)
        )
        lock_type = fcntl.LOCK_SH if options.report_only else fcntl.LOCK_EX
        private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="epub-triage-", dir="/tmp")))
        backend = Backend(config, private)
        evidence = backend.preflight()
        if evidence.get("daily_published_epoch"):
            print(f"Preflight passed. Daily signatures epoch {evidence['daily_published_epoch']}.", file=sys.stderr)
        queue_parent = config["queue"].parent
        root_identity = None
        locks = {}
        if root_fd is not None:
            info = os.fstat(root_fd)
            root_identity = info.st_dev, info.st_ino
            locks[root_identity] = root_fd
        if not options.report_only or queue_parent.exists():
            queue_fd = stack.enter_context(absolute_directory(queue_parent, create=not options.report_only))
            queue_stat = os.fstat(queue_fd)
            locks.setdefault((queue_stat.st_dev, queue_stat.st_ino), queue_fd)
        for _, descriptor in sorted(locks.items()):
            fcntl.flock(descriptor, lock_type)
        output_ids = set()
        for target in excluded:
            try:
                with absolute_directory(target) as output:
                    info = os.fstat(output)
            except FileNotFoundError:
                continue
            identity = (info.st_dev, info.st_ino)
            if identity == root_identity or identity in output_ids:
                raise RuntimeError("Intake and output directory identities must be distinct")
            output_ids.add(identity)
        state = stack.enter_context(State(config, root, root_fd, options.report_only, private))

        def in_scope(relative):
            if requested:
                return relative in requested and not blocked_path(root_fd, relative, output_ids)
            if options.no_recursive and "/" in relative:
                return False
            return (not any((root / relative).is_relative_to(path) for path in excluded)
                    and not blocked_path(root_fd, relative, output_ids))

        limits = {key: config[key] for key in DEFAULT_LIMITS}
        behavior = Behavior(state, private, limits)
        behavior.preflight()
        repair = Repair(state, backend, options, limits, private, validate_result, behavior) if repair_requested else None
        if options.command == "repair":
            return run_repairs(repair, None)
        journal = state.pending(in_scope)
        if requested:
            pending = [name for name in requested if not blocked_path(root_fd, name, output_ids)]
        else:
            pending = collect(root_fd, root, excluded, output_ids,
                              not options.no_recursive, options.report_only)
        pending += [relative for relative in journal if relative not in pending]
        failed = False
        for relative in pending:
            record = record_for(relative, root, options.report_only)
            if failed:
                record["error"] = "Batch stopped after an operational failure"
            else:
                try:
                    if relative in journal:
                        row = journal[relative]
                        record.update(json.loads(row["findings"]), sha256=row["sha256"],
                                      action=row["action"], status=row["status"], destination=row["target"])
                        pending_snapshot = private / "pending-behavior.epub"
                        try:
                            if row["action"] == "stage_repair":
                                static, gate, identity = state.pending_behavior(
                                    row, behavior, lambda book: validate_result(backend.inspect(book, limits)))
                                record.update(static, behavior=gate)
                                if gate and gate["effective"] == "hold":
                                    record.update(action="hold", status="behavior_pending", pending=True)
                                    counts["hold"] += 1
                                    emit(record)
                                    continue
                                if gate is None or gate["effective"] == "quarantine":
                                    record.update(action="quarantine",
                                                  status="behavior_quarantine" if gate else "quarantine")
                                    if not options.report_only:
                                        state.discard_pending_repair(row)
                                    state.apply(record, pending_snapshot, identity)
                                elif options.report_only:
                                    state.preview_pending(row)
                                else:
                                    state.finish(row)
                            elif options.report_only:
                                state.preview_pending(row)
                            else:
                                state.finish(row)
                            if options.report_only:
                                record["pending"] = True
                            else:
                                record["recovered"] = True
                        finally:
                            pending_snapshot.unlink(missing_ok=True)
                    else:
                        relpath = Path(relative)
                        with directory(root_fd, relpath.parts[:-1]) as parent:
                            with file_at(parent, relpath.name, preserve_atime=options.report_only) as source:
                                snapshot = private / "snapshot.epub"
                                try:
                                    sha256, source_identity, oversized = snap(source, snapshot, config["max_book_bytes"])
                                    record["sha256"] = sha256
                                    if oversized:
                                        record["security"]["findings"].append({
                                            "kind": "incomplete", "code": "book_limit",
                                            "detail": "Source size exceeds the configured inspection limit",
                                        })
                                    else:
                                        record.update(validate_result(backend.inspect(snapshot, limits)))
                                    record["action"], record["status"] = choose_action(record)
                                    if record["action"] != "quarantine":
                                        record["behavior"] = behavior.assess(snapshot, sha256)
                                        effective = record["behavior"]["effective"]
                                        if effective == "quarantine":
                                            record.update(action="quarantine", status="behavior_quarantine")
                                        elif effective == "hold":
                                            record.update(action="hold", status="behavior_hold")
                                    if record["action"] in {"quarantine", "stage_repair"}:
                                        state.apply(record, snapshot, source_identity)
                                finally:
                                    snapshot.unlink(missing_ok=True)
                    state.remember_head(record)
                except ERRORS as error:
                    failed = True
                    if record["action"] != "error":
                        record["intended_action"] = record["action"]
                    record.update(action="error", status="operational_error", error=str(error))
                    print(f"{relative!r}: {error!s}", file=sys.stderr)
            category = actions[record["action"]]
            if repair and record["action"] == "stage_repair":
                entries = list(repair.select([record]))
                if len(entries) != 1:
                    raise RuntimeError("Current scan did not identify exactly one repair intake")
                subrecord = repair_record(repair, entries[0])
                record["repair"] = subrecord
                if subrecord["decision"] == "error":
                    category = "errors"
                    failed = True
            counts[category] += 1
            emit(record)
    print(f"Books {sum(counts.values())}. Clean {counts['clean']}. Quarantine {counts['quarantine']}. "
          f"Repair {counts['repair']}. Held {counts['hold']}. Operational errors {counts['errors']}.", file=sys.stderr)
    return 2 if counts["errors"] else int(bool(counts["quarantine"] or counts["repair"] or counts["hold"]))


def repair_record(repair, entry, stopped=False):
    report = repair.record(entry)
    if stopped:
        report["error"] = "Batch stopped after an operational failure"
    else:
        try:
            repair.process(entry, report)
        except ERRORS as error:
            report.update(decision="error", action="error", status="operational_error", error=str(error))
            print(f"{entry['relative']!r}: {error!s}", file=sys.stderr)
    return report


def run_repairs(repair, scanned):
    failures = unresolved = 0
    for entry in repair.select(scanned):
        report = repair_record(repair, entry, stopped=bool(failures))
        if report["decision"] == "error":
            failures += 1
        if report["decision"] not in {"accepted", "unchanged"} or (report.get("quality") or {}).get("findings"):
            unresolved += 1
        emit(report)
    print(f"Repair entries requiring attention {unresolved}. Operational errors {failures}.", file=sys.stderr)
    return 2 if failures else int(bool(unresolved))


def main(argv=None):
    options = parse(argv)
    try:
        return run(options, configuration(options.config, options.folder, standalone=options.command == "repair" or options.command in REVIEW_COMMANDS | BEHAVIOR_COMMANDS))
    except ERRORS as error:
        print(f"Operational failure: {error!s}", file=sys.stderr)
        print("Batch stopped. Operational errors 1.", file=sys.stderr)
        return 2
