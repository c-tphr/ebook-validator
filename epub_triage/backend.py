"""Trusted preflight, FreshClam handoff, and fail-closed Bubblewrap launcher."""

from contextlib import ExitStack
import fcntl
import json
import os
import selectors
import signal
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time

from .state import absolute_directory, file_at


AGE_LIMIT = 72 * 3600
BIN = Path("/usr/bin")
REPO = Path(__file__).resolve().parent
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
MAX_RESPONSE = 1024 * 1024


class OfflineWorkerTimeout(RuntimeError):
    def __init__(self, operation):
        self.operation = operation
        super().__init__(f"Offline worker timed out during {operation}; inspection attribution unavailable")


def tool(name, *arguments, timeout=300):
    try:
        return subprocess.run([str(BIN / name), *map(str, arguments)], capture_output=True,
                              env=SAFE_ENV, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{name} did not finish within {timeout} seconds") from error



def bounded_worker(command, timeout, stdin=subprocess.DEVNULL, env=None):
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=SAFE_ENV if env is None else env, start_new_session=True) as process:
        with selectors.DefaultSelector() as watch:
            watch.register(process.stdout, selectors.EVENT_READ, bytearray())
            watch.register(process.stderr, selectors.EVENT_READ, bytearray())
            output = [watch.get_key(stream).data for stream in (process.stdout, process.stderr)]
            try:
                while watch.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in watch.select(remaining):
                        block = os.read(key.fd, 65536)
                        if not block:
                            watch.unregister(key.fileobj)
                        else:
                            key.data.extend(block)
                            if len(key.data) > MAX_RESPONSE:
                                raise RuntimeError("Offline worker output exceeds protocol limit")
                status = process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raise
    return status, *output

def age_is_fresh(epoch, now=None):
    return 0 <= (time.time() if now is None else now) - epoch <= AGE_LIMIT


class Backend:
    def __init__(self, config, private):
        self.config = config
        self.private = private
        self.signatures = private / "signatures"
        self.signatures.mkdir()
        self.epoch = None
        self.network_namespace = os.readlink("/proc/self/ns/net")
        self.worker_source = private / "worker"
        self.worker_source.mkdir()
        for name in ("__init__", "archive", "content", "repair_rules", "review_work", "worker"):
            (self.worker_source / (name + ".py")).write_bytes((REPO / (name + ".py")).read_bytes())

    def preflight(self):
        if os.geteuid() == 0:
            raise RuntimeError("Run the inspection supervisor as an unprivileged user")
        runtime = [Path(name).resolve() for name in ("/usr", "/bin", "/lib", "/lib64", "/etc/alternatives")]
        for key in ("folder", "quarantine", "repair", "queue", "database", "repaired_output"):
            if key not in self.config:
                continue
            location = self.config[key].resolve()
            if any(location.is_relative_to(item) or item.is_relative_to(location) for item in runtime):
                raise RuntimeError(f"{key} overlaps files visible in the worker runtime")
        control = self.private / "probe.epub"
        control.write_bytes(b"Read-only mount probe")
        evidence = self.invoke("isolation", control, json.dumps(self.config.get("worker_marker_paths", {})), timeout=20)
        if evidence.get("offline") is not True or evidence.get("read_only") is not True:
            raise RuntimeError("Isolation probe did not confirm offline, read-only access")
        for key in ("folder", "quarantine", "repair", "queue", "database", "repaired_output"):
            if key not in self.config:
                continue
            location = self.config[key]
            while not location.exists():
                location = location.parent
            filesystem = tool("stat", "-f", "-c", "%T", "--", location, timeout=5)
            if (filesystem.returncode or filesystem.stdout.strip() not in
                    {b"ext2/ext3", b"xfs", b"btrfs", b"overlayfs"}):
                raise RuntimeError(f"{key} requires a supported local Linux filesystem")
        epoch = self.load_signatures(refresh=self.config.get("refresh_signatures", True))
        if not age_is_fresh(epoch):
            raise RuntimeError("Daily ClamAV signatures are outside the 72-hour publisher window")
        self.epoch = epoch
        ready = self.invoke("ready", control, timeout=self.config.get("readiness_timeout", 180))
        if ready.get("ready") is not True:
            raise RuntimeError("Offline scanner and validator readiness could not be established")
        return {"daily_published_epoch": epoch, **evidence}

    def load_signatures(self, refresh):
        with absolute_directory(self.config["database"]) as database:
            fcntl.flock(database, fcntl.LOCK_EX)
            try:
                epoch = self.copy_generation(database)
            except FileNotFoundError:
                epoch = None
            if epoch is not None and age_is_fresh(epoch):
                return epoch
            if refresh:
                options = [f"--datadir={self.config['database']}"]
                if self.config.get("freshclam_config"):
                    options.append(f"--config-file={self.config['freshclam_config']}")
                result = tool("freshclam", *options)
                if result.returncode:
                    raise RuntimeError("FreshClam update failed: " +
                                       (result.stdout + result.stderr)[-700:].decode(errors="replace"))
                return self.copy_generation(database)
            raise RuntimeError("Daily signature database is missing or stale")

    def copy_generation(self, database):
        for old in self.signatures.iterdir():
            old.unlink()
        daily_epoch = None
        for base in ("main", "daily", "bytecode"):
            with ExitStack() as opened:
                candidates = []
                for extension in ("cvd", "cld"):
                    name = f"{base}.{extension}"
                    try:
                        stream = opened.enter_context(file_at(database, name))
                    except FileNotFoundError:
                        continue
                    candidates.append((name, stream))
                if not candidates:
                    raise FileNotFoundError(f"ClamAV database {base} is missing")
                if len(candidates) != 1:
                    raise RuntimeError(f"Conflicting CVD/CLD files for {base}")
                name, stream = candidates[0]
                metadata = os.fstat(stream.fileno())
                limit = 300 * 1024 * 1024
                if not 512 <= metadata.st_size <= limit:
                    raise RuntimeError(f"Unexpected signature file size for {name}")
                header = stream.read(512)
                fields = header.rstrip(b" \0\r\n").split(b":")
                if len(fields) != 9 or fields[0] != b"ClamAV-VDB" or not fields[8].isdigit():
                    raise RuntimeError(f"Missing publisher build epoch in {name}")
                stream.seek(0)
                copy = self.signatures / name
                with copy.open("xb") as target:
                    remaining = limit + 1
                    while remaining and (chunk := stream.read(min(1024 * 1024, remaining))):
                        target.write(chunk)
                        remaining -= len(chunk)
                current = os.fstat(stream.fileno())
                if (not remaining or copy.stat().st_size != metadata.st_size
                        or current.st_mtime_ns != metadata.st_mtime_ns
                        or current.st_ctime_ns != metadata.st_ctime_ns):
                    raise RuntimeError(f"Signature file changed during copy: {name}")
                if name.endswith(".cvd"):
                    result = tool("sigtool", "--info", copy, timeout=90)
                    if result.returncode or b"Verification OK" not in result.stdout + result.stderr:
                        raise RuntimeError(f"Vendor verification failed for {name}")
                    if base == "daily":
                        self.verify_inner_epoch(copy, fields)
                # CLDs are trusted only as output of the cooperating FreshClam
                # service. Arbitrary third-party local definitions are excluded.
                if base == "daily":
                    daily_epoch = int(fields[8])
        return daily_epoch

    @staticmethod
    def verify_inner_epoch(path, outer):
        try:
            with path.open("rb") as payload:
                payload.seek(512)
                with tarfile.open(fileobj=payload, mode="r|gz") as archive:
                    scanned_bytes = 0
                    for index, member in enumerate(archive):
                        scanned_bytes += member.size
                        if index > 128 or scanned_bytes > 512 * 1024 * 1024:
                            break
                        if member.name != "daily.info":
                            continue
                        if not member.isfile() or not 0 < member.size <= 4 * 1024 * 1024:
                            break
                        with archive.extractfile(member) as info:
                            inner = info.readline(1024).rstrip(b"\r\n").split(b":")
                        fields = (0, 1, 2, 3, 4, 7, 8)
                        if len(inner) == 9 and all(inner[index] == outer[index] for index in fields):
                            return
                        break
        except (EOFError, tarfile.TarError) as error:
            raise RuntimeError("Could not read authenticated daily CVD metadata") from error
        raise RuntimeError("Daily CVD publisher metadata differs from authenticated payload")

    def inspect(self, book, limits):
        if not age_is_fresh(self.epoch):
            raise RuntimeError("Daily signatures expired during the batch; rerun to refresh")
        return self.invoke("inspect", book, json.dumps(limits), timeout=self.config.get("inspection_timeout", 300))

    def inspect_repair(self, book, limits):
        self.require_fresh()
        return self.invoke("inspect-repair", book, json.dumps(limits),
                           timeout=self.config.get("inspection_timeout", 300))

    def plan_repair(self, book, limits, profile, candidate=None):
        self.require_fresh()
        if candidate is not None:
            with candidate.open("xb"):
                pass
        return self.invoke("plan-repair", book, json.dumps(limits), profile,
                           "build" if candidate is not None else "preview", candidate=candidate,
                           timeout=self.config.get("inspection_timeout", 300))

    def review_data(self, book, limits, request, candidate=None):
        self.require_fresh()
        if candidate is not None:
            with candidate.open("xb"):
                pass
        with tempfile.NamedTemporaryFile(dir=self.private) as data:
            data.write(json.dumps(request).encode())
            data.flush()
            return self.invoke("review-data", book, json.dumps(limits),
                               "build" if candidate is not None else "read", candidate=candidate,
                               request=Path(data.name),
                               timeout=self.config.get("inspection_timeout", 300))

    def require_fresh(self):
        if not age_is_fresh(self.epoch):
            raise RuntimeError("Daily signatures expired during the batch; rerun to refresh")

    def invoke(self, operation, book, *arguments, timeout, candidate=None, request=None):
        command = [
            "/usr/bin/bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--disable-userns", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "PATH", SAFE_ENV["PATH"], "--setenv", "LANG", SAFE_ENV["LANG"],
            "--setenv", "LC_ALL", SAFE_ENV["LC_ALL"], "--setenv", "HOME", "/tmp",
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--setenv", "PYTHONUTF8", "1",
            "--ro-bind", "/usr", "/usr", "--ro-bind-try", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64", "--ro-bind-try", "/bin", "/bin",
            "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
            "--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
            "--ro-bind-try", "/etc/java-21-openjdk", "/etc/java-21-openjdk",
            "--ro-bind-try", "/etc/java-17-openjdk", "/etc/java-17-openjdk",
            "--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev", "--size",
            str(self.config.get("inspection_tmp_bytes", 1024 * 1024 * 1024)),
            "--tmpfs", "/tmp", "--dir", "/app", "--ro-bind", str(self.worker_source),
            "/app/epub_triage", "--dir", "/input", "--ro-bind", str(book), "/input/book.epub",
            "--ro-bind", str(self.signatures), "/signatures", "--chdir", "/app",
        ]
        if request is not None:
            command += ["--ro-bind", str(request), "/request.json"]
        if candidate is not None:
            command += ["--bind", str(candidate), "/output.epub"]
        if operation != "isolation":
            jar = self.config["epubcheck_jar"]
            command += ["--dir", "/validator", "--ro-bind", str(jar), "/validator/epubcheck.jar"]
            dependencies = jar.parent / "lib"
            if dependencies.exists():
                command += ["--ro-bind", str(dependencies), "/validator/lib"]
        command += ["--remount-ro", "/", "--", "/usr/bin/python3", "-B", "-m", "epub_triage.worker",
                    operation, self.network_namespace, *arguments]
        try:
            status, output, diagnostics = bounded_worker(command, timeout)
        except subprocess.TimeoutExpired as error:
            raise OfflineWorkerTimeout(operation) from error
        if status:
            raise RuntimeError(f"Offline worker failed during {operation} ({status}): " +
                               diagnostics[-600:].decode(errors="replace"))
        result = json.loads(output)
        if not isinstance(result, dict):
            raise RuntimeError("Offline worker response is not an object")
        return result
