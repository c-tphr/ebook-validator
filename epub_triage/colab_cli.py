"""Pinned reviewer adapters and an isolated local bridge to the v3 text-only relay."""

from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from .backend import bounded_worker
from .colab_gemini import SCHEMA, wire
from .colab_runtime import MiB, WORKER_ID
from .review_cli import (INSTRUCTIONS, ReviewerUnavailable, native_command, relay, requested_model,
                         response_text)

AUTH = {"codex": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY", "agy": "GEMINI_API_KEY"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
TIMEOUT = 120


def fingerprint(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


class Dispatcher:
    def __init__(self, secret_loader):
        self.load = secret_loader
        self.binaries = {}
        self.local_routing = {}

    def configure(self, name, executable, digest, method, model=None):
        if name not in AUTH:
            raise ValueError("Select one of the supported reviewer CLIs.")
        if method != "secret-key":
            raise ReviewerUnavailable("This interactive authentication method needs a qualified isolated transport.")
        path = Path(executable).resolve(strict=True)
        if (not path.is_file() or not os.access(path, os.X_OK) or not HEX.fullmatch(digest)
                or fingerprint(path) != digest):
            raise ReviewerUnavailable("Reviewer executable does not match its approved native binary pin.")
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ReviewerUnavailable("Configure the pinned native Linux binary.")
        self.local_routing.pop(name, None)
        self.binaries[name] = (path, digest)
        if name == "agy":
            marker = secrets.token_hex(16)
            try:
                response = self.invoke(name, model, {"test": "public transport control"}, marker=marker)
            except ReviewerUnavailable:
                self.binaries.pop(name, None)
                raise ReviewerUnavailable("Antigravity did not pass the local provider-only routing probe.") from None
            if response.get("rationale") != marker:
                self.binaries.pop(name, None)
                raise ReviewerUnavailable("Antigravity did not return the mock transport marker.")
            self.local_routing[name] = model

    def readiness(self, name):
        if name == "agy":
            if name in self.local_routing:
                return "Local route passed. Effective native-tool denial has not been qualified."
            return "Pinned CLI and local routing probe pending. Native-tool denial also needs qualification."
        return "Pinned CLI configured; request a smoke test to check secret and model access." if (
            name in self.binaries) else "Restricted transport or approved native CLI pending."

    def __call__(self, name, config, payload):
        if name not in self.binaries:
            raise ReviewerUnavailable("Selected reviewer has no qualified native CLI configuration.")
        model = requested_model(name, config)
        if name == "agy":
            # Routing alone cannot prove the CLI denies in-process native tools.
            raise ReviewerUnavailable("Antigravity native-tool denial must qualify before account access.")
        try:
            credential = self.load(AUTH[name])
        except Exception:
            raise ReviewerUnavailable("Access to the selected reviewer secret did not complete.") from None
        if not isinstance(credential, str) or not 8 <= len(credential) <= 8192 or any(c in credential for c in "\r\n"):
            raise ReviewerUnavailable("The selected reviewer secret is missing.")
        return self.invoke(name, model, payload, credential=credential)

    def invoke(self, name, model, payload, credential=None, marker=None):
        source, pinned = self.binaries[name]
        seed = "EPUB_TRIAGE_REVIEW_V1\n" + json.dumps(payload, ensure_ascii=True) + "\n" + INSTRUCTIONS
        if len(seed) > 100 * 1024:
            raise ReviewerUnavailable("Review request exceeds the protocol bound.")
        ticket = secrets.token_urlsafe(32)
        try:
            with tempfile.TemporaryDirectory(prefix="review-v5-") as temporary, tempfile.TemporaryFile() as prompt:
                base = Path(temporary)
                scratch = base / "session"
                scratch.mkdir(mode=0o700)
                scratch.chmod(0o700)
                if os.geteuid() == 0:
                    os.chown(base, WORKER_ID, WORKER_ID)
                    os.chown(scratch, WORKER_ID, WORKER_ID)
                for directory in ("home", "work", "home/." + name):
                    path = scratch / directory
                    path.mkdir(mode=0o700)
                    if os.geteuid() == 0:
                        os.chown(path, WORKER_ID, WORKER_ID)
                executable = base / name
                with source.open("rb") as initial, executable.open("xb") as copy:
                    remaining = 512 * MiB + 1
                    while remaining and (chunk := initial.read(min(1024 * 1024, remaining))):
                        copy.write(chunk)
                        remaining -= len(chunk)
                if executable.stat().st_size > 512 * MiB or fingerprint(executable) != pinned:
                    raise ReviewerUnavailable("Pinned reviewer binary changed.")
                executable.chmod(0o555)
                endpoint = base / "relay.sock"
                shim = base / "bridge.py"
                shim.write_bytes(Path(__file__).with_name("colab_bridge.py").read_bytes())
                shim.chmod(0o444)
                prompt.write(seed.encode("ascii"))
                prompt.seek(0)
                if name == "agy":
                    settings = scratch / "home" / ".gemini" / "antigravity-cli"
                    settings.mkdir(parents=True)
                    if os.geteuid() == 0:
                        os.chown(settings.parent, WORKER_ID, WORKER_ID)
                        os.chown(settings, WORKER_ID, WORKER_ID)
                    configuration = settings / "settings.json"
                    configuration.write_text('{"modelProvider":"gemini"}')
                    configuration.chmod(0o444)
                    schema = scratch / "schema.json"
                    schema.write_text(json.dumps(SCHEMA))
                    schema.chmod(0o444)
                    transport = wire(endpoint, ticket=ticket, model=model, credential=credential, marker=marker)
                else:
                    transport = relay(name, TIMEOUT, ticket, unix=endpoint, credential=credential)
                with transport as state:
                    errors = state[0] if name == "agy" else state[1]
                    endpoint.chmod(0o600)
                    if os.geteuid() == 0:
                        os.chown(endpoint, WORKER_ID, WORKER_ID)
                    command = self.command(name, executable, scratch, endpoint, shim, model, ticket,
                                           agy_prompt=seed if name == "agy" else None)
                    status, output, _ = bounded_worker(command, TIMEOUT, stdin=prompt)
                    if status or errors or (marker and not state[1]):
                        raise ReviewerUnavailable("Selected reviewer process, authentication, or model is unavailable.")
                if credential and credential.encode() in output:
                    raise ReviewerUnavailable("Reviewer result included private transport data.")
                answer = agy_response(output) if name == "agy" else json.loads(response_text(name, output))
                if (not isinstance(answer, dict) or len(json.dumps(answer)) > 64 * 1024
                        or (credential and credential in json.dumps(answer))):
                    raise ReviewerUnavailable("Provider result failed output and secret checks.")
                return answer
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
            raise ReviewerUnavailable("Selected reviewer did not return a valid restricted response.") from None

    @staticmethod
    def command(name, executable, scratch, endpoint, shim, model, ticket, agy_prompt=None):
        netns = os.readlink("/proc/self/ns/net")
        outer = ["/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--cap-drop", "ALL",
                 "--die-with-parent", "--new-session", "--clearenv",
                 "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
                 "--ro-bind", "/usr/bin/bwrap", "/usr/bin/bwrap", "--ro-bind", "/usr/bin/python3", "/usr/bin/python3",
                 "--ro-bind", "/usr/lib", "/usr/lib", "--ro-bind-try", "/lib", "/lib",
                 "--ro-bind-try", "/lib64", "/lib64", "--ro-bind-try", "/usr/lib64", "/usr/lib64",
                 "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
                 "--ro-bind", str(shim), "/bridge.py", "--ro-bind", str(endpoint), "/relay.sock",
                 "--size", str(8 * MiB), "--tmpfs", "/tmp",
                 "--bind", str(scratch), str(scratch), "--ro-bind", str(executable), str(executable),
                 "--proc", "/proc", "--dev", "/dev"]
        outer += ["--remount-ro", "/", "--", "/usr/bin/python3", "-B", "/bridge.py",
                  "/relay.sock", netns]
        if name == "agy":
            inner = agy_sandbox(executable, scratch, ticket, model, agy_prompt)
        else:
            inner = native_command(name, executable, "http://127.0.0.1:{PORT}", model, scratch, ticket)
        index = inner.index("--tmpfs")
        inner[index:index] = ["--size", str(16 * MiB)]
        return (["/usr/bin/setpriv", f"--reuid={WORKER_ID}", f"--regid={WORKER_ID}",
                 "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
                 "--no-new-privs"] if os.geteuid() == 0 else []) + outer + inner


def agy_sandbox(executable, scratch, ticket, model, prompt):
    # These base variables are compatibility candidates. Configuration first
    # proves the pinned binary honors at least one, using no provider secret.
    return [
        "/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--disable-userns", "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "PATH", "/cli", "--setenv", "HOME", "/session/home",
        "--setenv", "XDG_CONFIG_HOME", "/session/home/.config", "--setenv", "TMPDIR", "/tmp",
        "--setenv", "GEMINI_API_KEY", ticket, "--setenv", "GOOGLE_GEMINI_BASE_URL", "http://127.0.0.1:{PORT}",
        "--setenv", "GEMINI_API_BASE_URL", "http://127.0.0.1:{PORT}",
        "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/usr/lib", "/usr/lib", "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind", str(executable), "/cli/agy", "--bind", str(scratch), "/session", "--tmpfs", "/tmp",
        "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc", "--remount-ro", "/",
        "--chdir", "/session/work", "--", *agy_command("/cli/agy", model, "/session/schema.json", prompt),
    ]


def agy_command(executable, model, schema, prompt):
    """Headless protocol shape. Callers must first qualify isolated egress and controls."""
    return [str(executable), "-p", prompt, "--model", model, "--mode", "plan",
            "--disable-slash-commands", "--output-format", "json", "--json-schema", str(schema),
            "--print-timeout", "90s"]


def agy_response(output):
    result = json.loads(output)
    if result.get("status") != "SUCCESS" or not isinstance(result.get("structured_output"), dict):
        raise ReviewerUnavailable("Antigravity headless output does not contain a successful structured result.")
    answer = result["structured_output"]
    if len(json.dumps(answer)) > 64 * 1024:
        raise ReviewerUnavailable("Antigravity response exceeds the protocol bound.")
    return answer
