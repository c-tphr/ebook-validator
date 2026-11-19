"""Trusted Colab dispatcher. Drive and provider credentials stay out of worker subprocesses."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import tempfile

from .backend import bounded_worker
from .colab_worker import BOOK_LIMIT, MiB, STATIC_TIMEOUT_OPERATIONS, limits_for

WORKER_ID = 62037
MARKERS = ("drive_mount", "credential_cache", "unrelated_book", "notebook_channel")
STAGING_PREFIX = "epub-v5-stage-"
LEASE = ".staging-lease"


def reap_abandoned(temp_root="/tmp"):
    """Remove only stale directories with this dispatcher’s locked, owned lease file."""
    if not shutil.rmtree.avoids_symlink_attacks:
        return 0
    cleared = 0
    for directory in Path(temp_root).glob(STAGING_PREFIX + "*"):
        descriptor = None
        try:
            outer = directory.lstat()
            if not stat.S_ISDIR(outer.st_mode) or outer.st_uid != os.geteuid() or outer.st_mode & 0o022:
                continue
            descriptor = os.open(directory / LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            lease = os.fstat(descriptor)
            if (not stat.S_ISREG(lease.st_mode) or lease.st_nlink != 1 or lease.st_uid != os.geteuid()
                    or lease.st_mode & 0o077 or os.read(descriptor, 64) != b"epub-validator-book-staging-v1\n"):
                continue
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if directory.lstat() != outer:
                continue
            shutil.rmtree(directory)
            cleared += 1
        except OSError:
            continue
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return cleared


class WorkerPending(RuntimeError):
    pass


class Runtime:
    def __init__(self, *, database, epubcheck_jar, behavior_python_packages=None, temp_root="/tmp", behavior_timeout=60):
        if type(behavior_timeout) is not int or not 60 <= behavior_timeout <= 600:
            raise ValueError("Behavioral reader timeout must be between 60 and 600 seconds.")
        self.abandoned_removed = reap_abandoned(temp_root)
        self.root = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=temp_root))
        self.lease = (self.root / LEASE).open("xb")
        (self.root / LEASE).chmod(0o600)
        fcntl.flock(self.lease, fcntl.LOCK_EX)
        self.lease.write(b"epub-validator-book-staging-v1\n")
        self.lease.flush()
        self.owner = (WORKER_ID, WORKER_ID) if os.geteuid() == 0 else (os.geteuid(), os.getegid())
        self.root.chmod(0o711)
        self.source = self.root / "app"
        package = self.source / "epub_triage"
        package.mkdir(mode=0o755, parents=True)
        self.source.chmod(0o755)
        package.chmod(0o755)
        for source in Path(__file__).parent.glob("*.py"):
            destination = package / source.name
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o444)
        self.config = {"database": str(database), "epubcheck_jar": str(epubcheck_jar),
                       "behavior_timeout": behavior_timeout}
        if behavior_python_packages:
            self.config["behavior_python_packages"] = str(behavior_python_packages)
        self.readiness = None

    def close(self):
        if not self.lease.closed:
            try:
                shutil.rmtree(self.root)
            finally:
                self.lease.close()

    @contextmanager
    def job(self):
        with (tempfile.TemporaryDirectory(prefix="job-", dir=self.root) as path,
              tempfile.TemporaryDirectory(prefix="outside-", dir=self.root) as controls):
            root = Path(path)
            os.chown(root, *self.owner)
            Path(controls).chmod(0o755)
            markers = {}
            for label in MARKERS:
                marker = Path(controls) / (label + "-" + secrets.token_hex(4))
                marker.write_bytes(b"disposable host-only control")
                marker.chmod(0o444)
                markers[label] = str(marker)
            yield root, {**self.config, "marker_paths": markers}

    def launch(self, job, request):
        instruction = job / "request.json"
        import socket
        for path in request["marker_paths"].values():
            if Path(path).read_bytes() != b"disposable host-only control":
                raise WorkerPending("Host marker positive control failed.")
        request = {**request, "controller_namespace": os.readlink("/proc/self/ns/net")}
        if request["operation"] == "setup":
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                with socket.create_connection(listener.getsockname(), timeout=2), listener.accept()[0]:
                    request["controller_loopback_positive"] = True
        instruction.unlink(missing_ok=True)
        with instruction.open("x") as target:
            json.dump(request, target, ensure_ascii=True)
        instruction.chmod(0o444)
        command = self.command(job)
        if os.geteuid() == 0:
            command = ["/usr/bin/setpriv", f"--reuid={self.owner[0]}", f"--regid={self.owner[1]}",
                       "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
                       "--bounding-set=-all", "--no-new-privs", *command]
        try:
            timeout = self.config["behavior_timeout"]
            limit = 240 + timeout * (8 if request["operation"] == "setup" else 4)
            status, output, diagnostics = bounded_worker(command, limit, env={
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            })
            if status:
                if b"setting up uid map" in diagnostics or b"No permissions to create" in diagnostics:
                    raise WorkerPending("User namespace setup was denied by the runtime kernel.")
                raise WorkerPending("Unprivileged worker failed. Inspection or isolation could not complete.")
            result = json.loads(output)
            if not isinstance(result, dict):
                raise ValueError("Invalid worker protocol.")
            if result.get("pending") == "static_timeout":
                stage = result.get("operation")
                if not isinstance(stage, str) or stage not in STATIC_TIMEOUT_OPERATIONS:
                    stage = "unknown"
                raise WorkerPending(f"Offline static worker timed out during {stage}. Work remains pending.")
            return result
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            raise WorkerPending("Unprivileged worker execution failed or exceeded its limits.") from error

    def command(self, job):
        # This namespace also contains the supervisor and strace. Nested
        # unprivileged namespaces are necessary for the existing production
        # tool boundaries. The outer namespace has no controller filesystem.
        command = [
            "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
            "--setenv", "HOME", "/nonexistent", "--setenv", "PYTHONNOUSERSITE", "1",
            "--setenv", "PYTHONPATH", "/app", "--ro-bind", "/usr", "/usr",
            "--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64", "--size", "4096", "--tmpfs", "/usr/local",
            "--remount-ro", "/usr/local",
        ]
        for path in ("/etc/ld.so.cache", "/etc/alternatives", "/etc/java-17-openjdk",
                     "/etc/java-21-openjdk", "/etc/fonts"):
            command += ["--ro-bind-try", path, path]
        command += ["--proc", "/proc", "--dev", "/dev",
                    "--size", str(8 * MiB), "--tmpfs", "/tmp",
                    "--ro-bind", str(self.source), "/app"]
        jar_directory = str(Path(self.config["epubcheck_jar"]).parent)
        locations = [jar_directory, self.config["database"]]
        if self.config.get("behavior_python_packages"):
            locations.append(self.config["behavior_python_packages"])
        for path in locations:
            command += ["--ro-bind", path, path]
        return command + ["--bind", str(job), str(job), "--chdir", "/app", "--remount-ro", "/",
                          "--", "/usr/bin/python3", "-B", "-s", "-m", "epub_triage.colab_worker", str(job)]

    def qualify(self):
        with self.job() as (job, request):
            self.readiness = self.launch(job, {**request, "operation": "setup"})
        return self.readiness

    def configuration(self):
        from hashlib import sha256
        implementation = {item.name: sha256(item.read_bytes()).hexdigest()
                          for item in (self.source / "epub_triage").glob("*.py")}
        readiness = self.readiness or {}
        scan = readiness.get("scan", {})
        stages = {engine: {key: value.get(key) for key in ("ready", "identity", "monitor",
                                                           "boundary_controls", "callback_controls")}
                  for engine, value in readiness.get("engines", {}).items()}
        return {"implementation": implementation,
                "scan": {key: scan.get(key) for key in ("ready", "daily_published_epoch")},
                "stages": stages, "tool_identity": getattr(self, "tool_identity", {}),
                "behavior_ready": readiness.get("behavior_ready", False),
                "behavior_timeout": self.config["behavior_timeout"]}

    @contextmanager
    def review(self, drive, scope, source, stage_bytes):
        if not self.readiness or not self.readiness.get("behavior_ready") or not self.readiness.get("scan", {}).get("ready"):
            raise WorkerPending("Both behavioral and static stages must be ready for review.")
        if source["size"] > BOOK_LIMIT:
            raise WorkerPending("Intake exceeds the configured static book limit.")
        limits_for(source["size"], stage_bytes)
        if shutil.disk_usage(self.root).free < stage_bytes:
            raise WorkerPending("Insufficient staging storage.")
        with self.job() as (job, request):
            scope.current(drive, source)
            book = job / "intake.epub"
            with book.open("xb") as sink:
                drive.read(source["id"], min(BOOK_LIMIT, stage_bytes), sink, source)
            book.chmod(0o444)

            def data(payload):
                scope.current(drive, source)
                result = self.launch(job, {**request, "operation": "review", "sha256": source["sha256"],
                                           "stage_bytes": stage_bytes, "review_request": payload})
                scope.current(drive, source)
                return result

            yield data

    def inspect(self, drive, scope, source, *, stage_bytes, report_only=True, profile=None, behavior=True, candidate_sink=None):
        if not self.readiness:
            raise WorkerPending("Run setup to qualify the local workers.")
        if not self.readiness.get("scan", {}).get("ready"):
            raise WorkerPending("The static worker and signatures are pending.")
        if behavior and not self.readiness.get("behavior_ready"):
            raise WorkerPending("Both real reader engines and monitors must pass before a batch can begin.")
        if source["size"] > BOOK_LIMIT:
            raise WorkerPending("Intake exceeds the configured static book limit.")
        limits_for(source["size"], stage_bytes)
        if profile not in {None, "mechanical", "broader"} or (profile and not behavior):
            raise ValueError("Unsupported repair profile.")
        if shutil.disk_usage(self.root).free < stage_bytes:
            raise WorkerPending("Insufficient free runtime storage for the selected staging budget.")
        with self.job() as (job, request):
            scope.current(drive, source)
            book = job / "intake.epub"
            with book.open("xb") as sink:
                drive.read(source["id"], min(BOOK_LIMIT, stage_bytes), sink, source)
            book.chmod(0o444)
            scope.current(drive, source)
            result = self.launch(job, {**request, "operation": "inspect", "sha256": source["sha256"],
                                       "stage_bytes": stage_bytes, "report_only": report_only,
                                       "profile": profile, "behavior": behavior})
            if result["sha256"] != source["sha256"]:
                raise WorkerPending("Worker reply disagrees with the verified intake bytes.")
            scope.current(drive, source)
            expected = (result.get("repair") or {}).get("output_sha256")
            if expected:
                from .colab_worker import digest
                candidate = job / "candidate.epub"
                if candidate.is_symlink() or not candidate.is_file() or digest(candidate) != expected:
                    raise WorkerPending("Candidate handoff differs from verified bytes.")
                if candidate_sink:
                    candidate_sink(candidate, expected)
            return result
