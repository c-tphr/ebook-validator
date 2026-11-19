"""Behavioral gate, evidence, and batch reader supervision."""

from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from .backend import REPO, bounded_worker
from .reader_worker import ENGINES, VIEW, file_target_fingerprint
from .state import State, absolute_directory, digest, directory, file_at, snap


LIMITS = {"behavior_timeout": (60, 600), "behavior_max_steps": (200, 500),
          "behavior_trace_days": (14, 365)}
COMMANDS = {"behavior-investigate", "behavior-override", "behavior-expire"}
ACTIONS = {"outbound_request", "out_of_book_read", "external_launch"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS behavior_results (
    sha256 TEXT NOT NULL, configuration_id TEXT NOT NULL, outcome TEXT NOT NULL,
    evidence TEXT NOT NULL, PRIMARY KEY (sha256, configuration_id)
);
CREATE TABLE IF NOT EXISTS behavior_overrides (
    sha256 TEXT NOT NULL, configuration_id TEXT NOT NULL, reason TEXT NOT NULL,
    created_at INTEGER NOT NULL, PRIMARY KEY (sha256, configuration_id),
    FOREIGN KEY (sha256, configuration_id) REFERENCES behavior_results (sha256, configuration_id)
);
CREATE TABLE IF NOT EXISTS behavior_decisions (
    id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, configuration_id TEXT NOT NULL,
    outcome TEXT NOT NULL, evidence TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS behavior_traces (
    id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, configuration_id TEXT NOT NULL,
    evidence TEXT NOT NULL, expires_at INTEGER NOT NULL
);
"""


class ReadersUnavailable(RuntimeError):
    pass


class MonitorUnavailable(RuntimeError):
    pass


class ReaderInterrupted(RuntimeError):
    def __init__(self, gap, events, *, monitor_failure=False):
        super().__init__(gap)
        self.events = events
        self.monitor_failure = monitor_failure


def stable(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def runtime_identity():
    locations = [Path("/usr/bin") / name for name in ("python3", "bwrap", "strace")]
    for root in (Path("/usr/share/fonts/truetype/dejavu"),):
        if root.is_dir():
            locations.extend(sorted(path for path in root.rglob("*") if path.is_file()))
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in locations}


def redacted(value):
    """Remove URLs and sensitive suffixes from all worker-controlled strings."""
    if isinstance(value, str):
        value = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>\"']+|(?i:\bmailto:[^\s<>\"']+)",
                       "[redacted URL]", value)
        return re.sub(r"(?<=[?#])[^\s<>\"']+", "[redacted value]", value)
    if isinstance(value, dict):
        return {key: redacted(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redacted(item) for item in value]
    return value


def syscall_evidence(diagnostics, mode, host_probe, marker_paths=None):
    """Read bounded independent syscall receipts from the monitored worker."""
    trace = diagnostics.decode(errors="replace")
    phase = "startup"
    step = None
    measurements = set()
    marker_paths = marker_paths or {}
    events = {}
    started = finished = False
    trigger = re.compile(r'^\s*(?:\[pid +(\d+)\] +)?([a-z0-9_]+)\((.*)')
    resumed = re.compile(r'^\s*(?:\[pid +(\d+)\] +)?<\.\.\. ([a-z0-9_]+) resumed>(.*)')
    unfinished = {}
    runtime = ("/usr/lib/", "/fonts/", "/lib/", "/lib64/", "/packages/", "/app/",
               "/tmp/", "/proc/self/", "/proc/thread-self/", "/dev/")
    expected = {"/app", ".", "/fonts", "/app/fonts.conf", "/etc/ld.so.cache", "/proc/filesystems",
                "/proc/mounts", "/proc/self/ns/net", "/etc/localtime", "/usr/share/qt5/qtlogging.ini",
                "/callback-receipts"}
    for line in trace.splitlines():
        if match := trigger.match(line):
            thread, name, detail = match.groups()
            if detail.endswith("<unfinished ...>"):
                unfinished[(thread, name)] = detail.removesuffix("<unfinished ...>")
                continue
        elif match := resumed.match(line):
            thread, name, detail = match.groups()
            if (thread, name) not in unfinished:
                continue
            detail = unfinished.pop((thread, name)) + detail
        else:
            continue
        if name == "prctl":
            if 'PR_SET_NAME, "epub-monitor-on"' in detail:
                started = True
            elif started and 'PR_SET_NAME, "epub-monitor-ok"' in detail:
                finished = True
            elif started and 'PR_SET_NAME, "epub-book"' in detail:
                phase = "inventory"
            elif started and (marker := re.search(r'PR_SET_NAME, "epub-step-(\d+)"', detail)):
                phase, step = "navigation", int(marker[1])
        if not started or finished:
            continue
        returned = re.search(r'= (-?\d+)(?: ([A-Z][A-Z0-9_]+)\b)?', detail)
        if not returned:
            # strace can split a call across thread interleavings. Reassemble
            # before interpreting such calls rather than inferring their outcome.
            continue
        denied = int(returned[1]) < 0
        status = returned[2] or ("failed" if denied else "success")
        target = None
        if name in {"execve", "execveat"}:
            action = "external_launch"
        elif name in {"connect", "socket", "socketpair", "sendto", "sendmsg", "sendmmsg", "io_uring_setup"}:
            action = ("outbound_request" if re.search(r"\bAF_INET6?\b", detail) else "local_ipc")
        elif name in {"open", "openat", "openat2"}:
            path = re.search(r'"([^"]*)"', detail)
            if not path:
                continue
            path = path[1]
            if path == host_probe and "ENOENT" in detail:
                measurements.add("host_read")
            for label, marker in marker_paths.items():
                if path == marker and "ENOENT" in detail:
                    measurements.add(label)
            if path == "/input/book.epub" or path in expected:
                if path == "/input/book.epub" and "O_RDWR" in detail and "EROFS" in detail:
                    measurements.add("read_only")
                continue
            if path.startswith(runtime) and ".." not in path.split("/"):
                continue
            # The working directory contains only trusted worker source. No
            # archive members have filesystem paths visible to the renderer.
            if not path.startswith("/") and path.startswith(("epub_triage/", "/app/")):
                continue
            action = "out_of_book_read" if "O_WRONLY" not in detail else "local_ipc"
            if action == "out_of_book_read":
                target = file_target_fingerprint(path)
        else:
            continue
        if name == "socket" and "AF_INET" in detail and "EPERM" in detail:
            for kind in ("STREAM", "DGRAM"):
                if "SOCK_" + kind in detail:
                    measurements.add(kind)
        if action == "external_launch" and "EPERM" in detail:
            measurements.add("dispatch")
        if mode != "health":
            arguments = re.sub(r"0x[0-9a-f]+", "<address>", detail[:returned.start()])
            key = stable(["independent-syscall-v1", name, arguments, phase, step])
            events[key] = {"action": action,
                           "attribution": "reader" if phase == "startup" or mode == "comparison" else "ambiguous",
                           "evidence": "observed_reader_syscall",
                           "event_id": key, "initiator": name, "phase": phase, "step": step,
                           "blocked": denied, "syscall_result": status}
            if target:
                events[key]["file_target_fingerprint"] = target
    if not started or not finished or re.search(r"^strace:", trace, re.M) or unfinished:
        raise MonitorUnavailable("Independent reader monitor did not complete")
    if mode == "health" and measurements != ({"host_read", "read_only", "STREAM", "DGRAM", "dispatch"} | set(marker_paths)):
        raise RuntimeError("Independent monitor positive control failed")
    return {"events": list(events.values()), "controls": sorted(measurements)}


def corroborating_book_request(event, records, steps):
    """Correlate a native file read with a distinct, authenticated resource request."""
    index = event.get("step")
    fingerprint = event.get("file_target_fingerprint")
    if (event.get("evidence") != "observed_reader_syscall" or event.get("action") != "out_of_book_read"
            or not fingerprint or type(index) is not int or not 0 <= index < len(steps)):
        return None
    return next((record["event_id"] for record in records
                 if record.get("evidence") == "renderer_resource_request"
                 and record.get("action") == "out_of_book_read"
                 and record.get("attribution") == "book" and record.get("blocked") is True
                 and record.get("step") == index and record.get("member") == steps[index]["member"]
                 and record.get("file_target_fingerprint") == fingerprint
                 and record.get("event_id") and record.get("event_id") != event.get("event_id")), None)


class ReaderBackend:
    def __init__(self, config, private):
        self.config = config
        runtime = [Path(name).resolve() for name in ("/usr/lib", "/usr/lib64", "/lib", "/lib64",
                                                   "/usr/share/fonts/truetype/dejavu")]
        if config.get("behavior_python_packages"):
            runtime.append(config["behavior_python_packages"].resolve(strict=True))
        for key in ("folder", "quarantine", "repair", "queue", "database", "repaired_output"):
            if key in config:
                path = config[key].resolve()
                if any(path.is_relative_to(root) or root.is_relative_to(path) for root in runtime):
                    raise ReadersUnavailable(f"{key} overlaps reader runtime files")
        self.network_namespace = os.readlink("/proc/self/ns/net")
        self.worker_source = private / "readers"
        self.worker_source.mkdir()
        for name in ("__init__", "archive", "reader_worker"):
            (self.worker_source / (name + ".py")).write_bytes((REPO / (name + ".py")).read_bytes())
        self.fonts = self.worker_source.parent / "reader-fonts.conf"
        self.fonts.write_text('<?xml version="1.0"?><fontconfig><dir>/fonts</dir>'
                              '<cachedir>/tmp/font-cache</cachedir></fontconfig>')
        self.control = self.worker_source.parent / "reader-control"
        self.control.write_bytes(b"Reader mount probe")
        self.host_probe = self.worker_source.parent / "host-only-reader-control"
        self.host_probe.write_bytes(b"Host-only isolation probe")

    def health(self, engine):
        return self.invoke(engine, "health", self.control, {},
                           {"marker_paths": self.config.get("worker_marker_paths", {})})

    def run(self, engine, book, limits, options, comparison=False):
        return self.invoke(engine, "comparison" if comparison else "run", book, limits, options)

    def callback_receipts(self, path):
        events = []
        valid = True
        with path.open("rb") as stream:
            data = stream.read(262145)
        if len(data) > 262144 or (data and not data.endswith(b"\n")):
            valid = False
        for raw in data.splitlines():
            try:
                event = json.loads(raw)
                required = {"action", "scheme", "step", "member", "attribution", "phase", "initiator",
                            "evidence", "blocked", "event_id"}
                marker = event.get("file_target_fingerprint")
                if (not required <= set(event) <= required | {"file_target_fingerprint"}
                        or (marker and (event["scheme"] != "file" or not re.fullmatch(r"[a-f0-9]{64}", marker)))
                        or event["action"] not in {"outbound_request", "out_of_book_read"}
                        or event["scheme"] not in {"http", "https", "ftp", "file", ""}
                        or event["attribution"] != "book" or event["phase"] != "navigation"
                        or event["initiator"] != "renderer_resource_callback"
                        or event["evidence"] != "renderer_resource_request" or event["blocked"] is not True
                        or not isinstance(event["member"], str) or not event["member"]
                        or type(event["step"]) is not int or not 0 <= event["step"] < 500
                        or not re.fullmatch(r"[a-f0-9]{64}", event["event_id"])):
                    raise ValueError("Malformed callback receipt")
                events.append(event)
            except (TypeError, ValueError, AttributeError):
                valid = False
                break
        return events, valid

    def invoke(self, engine, mode, book, limits, options):
        if os.geteuid() == 0:
            raise ReadersUnavailable("Run behavioral readers as an unprivileged user")
        command = [
            "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "PATH", "/usr/bin",
            "--setenv", "HOME", "/tmp", "--setenv", "XDG_CACHE_HOME", "/tmp/cache",
            "--setenv", "XDG_CONFIG_HOME", "/tmp/config", "--setenv", "XDG_DATA_HOME", "/tmp/data",
            "--setenv", "QT_QPA_PLATFORM", "offscreen", "--setenv", "LC_ALL", "C.UTF-8",
            "--setenv", "FONTCONFIG_FILE", "/app/fonts.conf", "--setenv", "XDG_RUNTIME_DIR", "/tmp/runtime",
            "--setenv", "PYTHONNOUSERSITE", "1", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--ro-bind", "/usr/bin/python3", "/usr/bin/python3",
            "--ro-bind", "/usr/lib", "/usr/lib", "--ro-bind-try", "/usr/lib64", "/usr/lib64",
            "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind", "/usr/share/fonts/truetype/dejavu", "/fonts",
            "--ro-bind", str(self.fonts), "/app/fonts.conf",
            "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
            "--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev", "--size",
            str(self.config.get("reader_tmp_bytes", 768 * 1024 * 1024)), "--tmpfs", "/tmp",
            "--ro-bind", str(self.worker_source), "/app/epub_triage", "--chdir", "/app",
            "--ro-bind", str(book), "/input/book.epub",
        ]
        if packages := self.config.get("behavior_python_packages"):
            command += ["--ro-bind", str(packages), "/packages", "--setenv", "PYTHONPATH", "/packages"]
        with tempfile.NamedTemporaryFile(dir=self.worker_source.parent) as receipts:
            path = Path(receipts.name)
            if mode in {"health", "run"}:
                command += ["--bind", str(path), "/callback-receipts", "--setenv", "EPUB_CALLBACK_RECEIPTS", "1"]
            return self.execute(command, engine, mode, limits, options, path)

    def execute(self, command, engine, mode, limits, options, path):
        command += ["--remount-ro", "/", "--", "/usr/bin/python3", "-B", "-m", "epub_triage.reader_worker",
                    engine, mode, self.network_namespace, json.dumps(limits), json.dumps(options),
                    str(self.host_probe)]
        command = ["/usr/bin/strace", "-f", "-qq", "-s", "512", "-e",
                   "trace=prctl,open,openat,openat2,execve,execveat,socket,socketpair,connect,"
                   "sendto,sendmsg,sendmmsg,io_uring_setup",
                   *command]
        try:
            status, output, diagnostics = bounded_worker(command, self.config.get("behavior_timeout", 60))
        except subprocess.TimeoutExpired:
            events, valid = self.callback_receipts(path)
            raise ReaderInterrupted("Reader timed out", events, monitor_failure=not valid)
        except RuntimeError as error:
            events, _ = self.callback_receipts(path)
            raise ReaderInterrupted("Reader monitor transport failed", events, monitor_failure=True) from error
        events, valid = self.callback_receipts(path)
        if not valid:
            raise ReaderInterrupted("Renderer callback receipt was incomplete", events, monitor_failure=True)
        if status:
            if "epub-monitor-on" not in diagnostics.decode(errors="replace"):
                raise ReaderInterrupted(f"{engine} monitor did not start", events, monitor_failure=True)
            raise ReaderInterrupted(f"{engine} reader process failed with status {status}", events)
        try:
            result = json.loads(output)
            observed = syscall_evidence(diagnostics, mode, str(self.host_probe), options.get("marker_paths"))
            if mode == "health":
                result["boundary_controls"] = observed["controls"]
                if {event["action"] for event in events} != {"outbound_request", "out_of_book_read"}:
                    raise MonitorUnavailable("Independent callback channel positive control failed")
                result["callback_controls"] = sorted({event["action"] for event in events})
            else:
                if mode == "run" and result["events"] != events:
                    raise MonitorUnavailable("Independent callback receipts differ from the renderer response")
                result["events"].extend(observed["events"])
                result["monitor"] = "renderer-callback+syscalls-v1"
                if any(step.get("status") == "completed" and (
                        not step.get("pages") or any(type(page) is not int or page < 1 for page in step["pages"]))
                       for step in result["steps"]):
                    raise MonitorUnavailable("Renderer page receipt missing")
            return result
        except (KeyError, ValueError, TypeError, AttributeError, MonitorUnavailable) as error:
            raise ReaderInterrupted("Reader monitor did not return valid evidence", events,
                                    monitor_failure=True) from error


class Behavior:
    def __init__(self, state, private, limits):
        self.state, self.private, self.limits = state, private, limits
        self.connection = state.connection
        self.backend = None
        self.configuration = None
        self.identifier = None

    def schema(self):
        if self.connection is None:
            return False
        if not self.state.preview:
            self.connection.executescript(SCHEMA)
        return self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='behavior_results'").fetchone() is not None

    def expire(self):
        if not self.schema() or self.state.preview:
            return 0
        self.connection.execute("PRAGMA secure_delete=ON")
        with self.connection:
            return self.connection.execute("DELETE FROM behavior_traces WHERE expires_at <= ?",
                                           (int(time.time()),)).rowcount

    def preflight(self):
        if self.configuration is not None:
            return
        try:
            self.backend = ReaderBackend(self.state.config, self.private)
        except (OSError, RuntimeError) as error:
            raise ReadersUnavailable("Behavioral batch paused. Reader runtime unavailable.") from error
        health = {}
        for engine in ENGINES:
            try:
                evidence = self.backend.health(engine)
                if (evidence.get("ready") is not True or not evidence.get("monitor")
                        or evidence.get("identity", {}).get("engine") != engine
                        or not evidence["identity"].get("renderer") or not evidence["identity"].get("version")):
                    raise RuntimeError("Incomplete engine or monitor readiness")
            except (OSError, ValueError, TypeError, AttributeError, RuntimeError, subprocess.TimeoutExpired) as error:
                raise ReadersUnavailable(f"Behavioral batch paused. {engine} engine or monitor unavailable.") from error
            health[engine] = evidence
        if len({value["identity"]["renderer"] for value in health.values()}) != len(ENGINES):
            raise ReadersUnavailable("Behavioral batch paused. Renderer identities are not distinct.")
        config = self.state.config
        self.options = {"max_steps": config.get("behavior_max_steps", 200)}
        self.configuration = {"engines": health, "profile": "reflowable-static-xhtml-v1",
                              "viewport": list(VIEW), "font": "DejaVu Sans",
                              "navigation": ["spine", "rendered-links", "toc", "destination-anchors"],
                              "options": self.options, "archive_limits": self.limits,
                              "timeout": config.get("behavior_timeout", 60), "policy": 1,
                              "platform": list(os.uname()),
                              "dependency_path": str(config.get("behavior_python_packages", "/usr/lib")),
                              "runtime": runtime_identity(),
                              "implementation": {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                                                 for name in ("reader_worker.py", "behavior.py", "archive.py")}}
        self.identifier = stable(self.configuration)
        self.expire()

    def result_for(self, sha256):
        if self.schema():
            return self.connection.execute(
                "SELECT outcome,evidence FROM behavior_results WHERE sha256=? AND configuration_id=?",
                (sha256, self.identifier)).fetchone()
        return None

    def effective(self, result, reused):
        override = None
        if result["outcome"] == "hold" and self.schema():
            row = self.connection.execute(
                "SELECT reason,created_at FROM behavior_overrides WHERE sha256=? AND configuration_id=?",
                (result["sha256"], self.identifier)).fetchone()
            if row:
                override = dict(row)
        return {**result, "reused": reused, "override": override,
                "effective": "release" if override else result["outcome"]}

    def override(self, sha256, configuration, reason):
        if self.state.preview or not reason.strip() or len(reason) > 1000:
            raise ValueError("Supply a nonempty hold override reason of at most 1000 characters")
        self.schema()
        with self.connection:
            row = self.connection.execute(
                "SELECT outcome,evidence FROM behavior_results WHERE sha256=? AND configuration_id=?",
                (sha256, configuration)).fetchone()
            if row is None or row["outcome"] != "hold" or not json.loads(row["evidence"]).get("overrideable", True):
                raise ValueError("Override requires an existing review hold for the exact SHA-256 and configuration")
            self.connection.execute("INSERT INTO behavior_overrides VALUES (?, ?, ?, ?)",
                                    (sha256, configuration, redacted(reason.strip()), int(time.time())))
        self.identifier = configuration
        return self.effective(json.loads(row["evidence"]), False)

    def read_engine(self, engine, book, comparison=False, itinerary=()):
        try:
            options = self.options if not comparison else {**self.options, "control_itinerary": itinerary}
            result = self.backend.run(engine, book, self.limits, options, comparison=comparison)
            if (type(result.get("complete")) is not bool or
                    any(not isinstance(result.get(key), list) for key in ("steps", "gaps", "events"))
                    or any(not isinstance(event, dict) for event in result["events"])):
                raise MonitorUnavailable("Invalid reader or monitor evidence")
            if any(not isinstance(step, dict) or step.get("kind") not in {
                       "reading_order", "internal", "footnote", "toc_document", "toc", "ncx"}
                   or not isinstance(step.get("member"), str) or not isinstance(step.get("fragment"), str)
                   or step.get("status") not in {"completed", "skipped", "pending"}
                   for step in result["steps"]):
                raise MonitorUnavailable("Invalid navigation evidence")
            if any(event.get("action") not in ACTIONS | {"local_ipc"} or type(event.get("blocked")) is not bool
                   or event.get("attribution") not in {"book", "reader", "ambiguous"}
                   or not isinstance(event.get("evidence"), str) for event in result["events"]):
                raise MonitorUnavailable("Invalid event evidence")
            if (result["gaps"] or any(step.get("status") != "completed" or
                                      not isinstance(step.get("pages"), list) or not step["pages"] or
                                      any(type(page) is not int or page < 1 for page in step["pages"])
                                      for step in result["steps"])
                    or (not comparison and not any(step.get("kind") == "reading_order" for step in result["steps"]))):
                if not result["gaps"]:
                    result["gaps"].append("Required navigation did not complete")
                result["complete"] = False
            return redacted(result)
        except ReaderInterrupted as error:
            return {"complete": False, "steps": [], "gaps": [str(error)], "events": redacted(error.events),
                    "monitor_failure": error.monitor_failure}
        except MonitorUnavailable:
            return {"complete": False, "steps": [], "gaps": ["Independent reader monitor failed"],
                    "events": [], "monitor_failure": True}
        except subprocess.TimeoutExpired:
            gap = "Reader timed out"
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            gap = "Reader crashed or monitor evidence was unavailable"
        return {"complete": False, "steps": [], "gaps": [gap], "events": []}

    def assess(self, book, sha256):
        with book.open("rb") as source:
            if digest(source) != sha256:
                raise RuntimeError("Behavior input differs from its expected SHA-256")
        self.preflight()
        existing = self.result_for(sha256)
        if existing:
            prior = self.effective(json.loads(existing["evidence"]), True)
            if prior["outcome"] in {"release", "quarantine"} or prior["override"]:
                return prior
        engines = {}
        flags = set()
        for engine in ENGINES:
            result = self.read_engine(engine, book)
            events = result["events"]
            comparison = None
            if any(event["attribution"] == "ambiguous" for event in events):
                suspect = {event.get("step") for event in events if event["attribution"] == "ambiguous"}
                itinerary = [(index, step["kind"], max(1, len(step.get("pages") or [])))
                             for index, step in enumerate(result["steps"]) if index in suspect]
                comparison = self.read_engine(engine, book, comparison=True, itinerary=itinerary)
                result["comparison"] = comparison
            for event in events:
                if event["attribution"] == "ambiguous":
                    matched = [control for control in comparison["events"]
                               if event.get("event_id") and control.get("event_id") == event["event_id"]
                               and all(control.get(key) == event.get(key) for key in
                                       ("action", "initiator", "phase", "step", "blocked", "syscall_result"))]
                    reader_control = any(control["attribution"] == "reader" for control in matched)
                    witness = corroborating_book_request(event, events, result["steps"])
                    if comparison["complete"] and witness and not matched:
                        event.update(attribution="book", resolution="matched original renderer file request",
                                     corroborated_by=witness, member=result["steps"][event["step"]]["member"])
                    elif comparison["complete"] and reader_control and not witness:
                        event.update(attribution="reader", resolution="matched authenticated reader control")
                    elif comparison["complete"] and any(
                        control["attribution"] == "book" and control["evidence"] == "authenticated_book_replay"
                        for control in matched):
                        event.update(attribution="book", resolution="matched authenticated book replay")
                    else:
                        event["resolution"] = "unresolved after one comparison"
                if event["action"] in ACTIONS:
                    flags.add(event["attribution"])
                elif event["attribution"] != "reader":
                    flags.add("ambiguous")
            if not result["complete"]:
                flags.add("incomplete")
            engines[engine] = result
        with book.open("rb") as source:
            if digest(source) != sha256:
                raise RuntimeError("Behavior input changed during rendering")
        plans = [[(step.get("kind"), step.get("member"), step.get("fragment"))
                  for step in result["steps"]] for result in engines.values()]
        external_counts = [result.get("external_links_unactivated") for result in engines.values()]
        if plans[0] != plans[1] or external_counts[0] != external_counts[1]:
            for result in engines.values():
                result["gaps"].append("Engines reported different navigation plans")
            flags.add("incomplete")
        outcome = "quarantine" if "book" in flags else "hold" if flags & {"ambiguous", "incomplete"} else "release"
        full = {"sha256": sha256, "configuration_id": self.identifier, "configuration": self.configuration,
                "engines": engines, "outcome": outcome,
                "overrideable": outcome == "hold" and not any(
                    result.get("monitor_failure") or result.get("comparison", {}).get("monitor_failure")
                    for result in engines.values())}
        durable = {**full, "engines": {engine: {key: value for key, value in result.items()
                                                 if key != "diagnostics"} for engine, result in engines.items()}}
        expires = int(time.time()) + self.state.config.get("behavior_trace_days", 14) * 86400
        if outcome != "release" and not self.state.preview:
            durable["temporary_trace"] = {"storage": "behavior_traces", "expires_at": expires}
        if not self.state.preview:
            with self.connection:
                # Incomplete runs remain pending and retryable absent a user override.
                self.connection.execute("INSERT INTO behavior_results VALUES (?, ?, ?, ?) "
                                        "ON CONFLICT(sha256,configuration_id) DO UPDATE "
                                        "SET outcome=excluded.outcome,evidence=excluded.evidence",
                                        (sha256, self.identifier, outcome, json.dumps(durable)))
                self.connection.execute("INSERT INTO behavior_decisions "
                                        "(sha256,configuration_id,outcome,evidence,created_at) VALUES (?, ?, ?, ?, ?)",
                                        (sha256, self.identifier, outcome, json.dumps(durable), int(time.time())))
                if outcome != "release":
                    self.connection.execute("INSERT INTO behavior_traces (sha256,configuration_id,evidence,expires_at) "
                                            "VALUES (?, ?, ?, ?)", (sha256, self.identifier, json.dumps(full),
                                             expires))
        return self.effective(durable, False)


def run_command(options, config, limits, emit):
    preview = options.report_only
    with ExitStack() as stack:
        private = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="epub-behavior-", dir="/tmp")))
        queue = config["queue"].parent
        if not preview or queue.exists():
            lock = stack.enter_context(absolute_directory(queue, create=not preview, preserve_atime=preview))
            fcntl.flock(lock, fcntl.LOCK_SH if preview else fcntl.LOCK_EX)
        state = stack.enter_context(State(config, config.get("folder"), None, preview, private))
        behavior = Behavior(state, private, limits)
        if options.command == "behavior-expire":
            emit({"expired_traces": behavior.expire()})
            return 0
        if options.command == "behavior-override":
            emit(behavior.override(options.sha256, options.configuration_id, options.reason))
            return 0
        root = config["quarantine"]
        rel = Path(options.book)
        if rel.is_absolute() or ".." in rel.parts or rel.suffix.lower() != ".epub":
            raise ValueError("Select an EPUB path relative to the quarantine directory")
        with absolute_directory(root, preserve_atime=preview) as parent:
            with directory(parent, rel.parts[:-1], preserve_atime=preview) as folder:
                with file_at(folder, rel.name, preserve_atime=preview) as source:
                    snapshot = private / "quarantined.epub"
                    sha256, _, oversized = snap(source, snapshot, limits["max_book_bytes"])
        if oversized:
            raise ValueError("Quarantined book exceeds the configured inspection limit")
        result = behavior.assess(snapshot, sha256)
        emit({"path": str(rel), "sha256": sha256, "action": "quarantine", "status": "quarantine",
              "report_only": preview, "behavior": result})
        return 1
