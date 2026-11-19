"""Run genuine CLI disposition checks against disposable fixtures on a provisioned Linux/WSL host."""

import argparse
from contextlib import ExitStack, closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import tomllib
from zipfile import ZipFile

from acceptance.fixtures import book
from epub_triage.worker import EICAR


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", required=True, type=Path, help="read scanner, updater and EPUBCheck paths only"
    )
    parser.add_argument(
        "--work-parent",
        required=True,
        type=Path,
        help="existing native Linux directory for temporary intake",
    )
    parser.add_argument(
        "--output-parent",
        type=Path,
        help="existing directory, optionally on a second Linux filesystem",
    )
    args = parser.parse_args()
    config_file = args.config.absolute()
    settings = tomllib.loads(config_file.read_text())
    runner = Path(__file__).resolve().parents[1] / "epub-triage"
    with ExitStack() as stack:
        work = Path(
            stack.enter_context(tempfile.TemporaryDirectory(dir=args.work_parent.resolve()))
        )
        output = Path(
            stack.enter_context(
                tempfile.TemporaryDirectory(dir=(args.output_parent or args.work_parent).resolve())
            )
        )
        folder = work / "books"
        config = dict(
            folder=folder, quarantine=output / "q", repair=output / "r", queue=work / "queue.sqlite"
        )
        for name in ("database", "epubcheck_jar", "freshclam_config"):
            if name in settings:
                config[name] = (config_file.parent / settings[name]).absolute()
        active = work / "config.toml"
        paths = "".join(f"{k} = {json.dumps(str(v))}\n" for k, v in config.items())
        timeouts = "".join(
            f"{key} = {json.dumps(settings[key])}\n"
            for key in ("readiness_timeout", "inspection_timeout")
            if key in settings
        )
        active.write_text(paths + timeouts)
        expected = {
            "clean": "leave",
            "click": "leave",
            "script": "quarantine",
            "both": "quarantine",
            "remote": "quarantine",
            "unlisted": "quarantine",
            "unsafe": "quarantine",
            "corrupt": "quarantine",
            "signature": "quarantine",
            "nav": "stage_repair",
            "manifest": "stage_repair",
            "heuristic": "stage_repair",
        }
        hashes = {}
        for kind in expected:
            src = folder / (kind + ".epub")
            book(src, kind)
            if kind == "signature":
                with ZipFile(src, "a") as archive:
                    archive.writestr("antivirus-control.txt", EICAR)
            hashes[src.name] = hashlib.sha256(src.read_bytes()).hexdigest()
        proc = subprocess.run([runner, "--config", active], capture_output=True, text=True)
        print(proc.stderr, end="")
        print(proc.stdout, end="")
        if proc.returncode != 1:
            raise SystemExit(f"Expected findings exit 1, received {proc.returncode}")
        records = [json.loads(line) for line in proc.stdout.splitlines()]
        if len(records) != len(expected) or {r["path"] for r in records} != set(hashes):
            raise SystemExit("Unexpected batch membership")
        for r in records:
            kind = Path(r["path"]).stem
            if (
                r["action"] != expected[kind]
                or r["sha256"] != hashes[r["path"]]
                or Path(r["source"]).exists() != (expected[kind] != "quarantine")
            ):
                raise SystemExit(f"Disposition or source hash mismatch for {kind}")
            if kind == "signature" and not any(
                f["kind"] == "malware" for f in r["security"]["findings"]
            ):
                raise SystemExit("Expected a real signature match for the harmless AV control")
            if (
                r["destination"]
                and hashlib.sha256(Path(r["destination"]).read_bytes()).hexdigest() != r["sha256"]
            ):
                raise SystemExit(f"Destination hash mismatch for {kind}")
        with closing(sqlite3.connect(config["queue"])) as conn:
            rows = conn.execute(
                "select source, status, sha256, repair_copy from repair_queue"
            ).fetchall()
        if {Path(src).stem for src, *_ in rows} != {"heuristic", "manifest", "nav"} or len(
            rows
        ) != 3:
            raise SystemExit("Unexpected repair queue membership")
        for src, status, sha, copy in rows:
            if (status == "needs_review") != (Path(src).stem == "heuristic") or not all(
                hashlib.sha256(Path(p).read_bytes()).hexdigest() == sha for p in (src, copy)
            ):
                raise SystemExit(f"Queue verification failed for {src}")
        print(f"PASS {len(records)} dispositions, {len(rows)} verified repair copies")


if __name__ == "__main__":
    main()
