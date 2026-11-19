"""Run real ClamAV and EPUBCheck over generated Linux repair pairs with relocated binaries.

Use only with the benign fixtures. This harness does not provide namespace isolation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
from zipfile import ZipFile

from acceptance.v2_fixtures import write_book
from epub_triage import repair, repair_rules, worker
from epub_triage.cli import DEFAULT_LIMITS, validate_result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("clamscan", "database", "jar"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--library-path")
    args = parser.parse_args()
    limits = {key: spec[0] for key, spec in DEFAULT_LIMITS.items()}

    with tempfile.TemporaryDirectory() as folder:
        base = Path(folder)

        def inspect(book, label):
            scratch = base / label
            scratch.mkdir()

            def capture(cmd, limit=2 * 1024 * 1024):
                substitutions = {
                    "/usr/bin/clamscan": str(args.clamscan),
                    "--database=/signatures": "--database=" + str(args.database),
                    "/validator/epubcheck.jar": str(args.jar),
                }
                command = [substitutions.get(str(token), str(token)) for token in cmd]
                env = os.environ.copy()
                if args.library_path:
                    env["LD_LIBRARY_PATH"] = args.library_path
                run = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                    env=env,
                    timeout=300,
                )
                assert len(run.stdout) <= limit
                return run.returncode, run.stdout.decode()

            def relocate(value):
                return (
                    scratch / "report.json"
                    if str(value) == "/tmp/conformance.json"
                    else Path(value)
                )

            with patch.object(worker, "run_capture", capture), patch.object(
                worker, "Path", relocate
            ):
                return validate_result(
                    worker.inspect(book, limits, scratch, occurrences=True)
                )

        for name, settings, profile, expected in [
            (
                "mixed-mechanical",
                dict(case=True, layout=True, warning=True),
                "mechanical",
                {"M1"},
            ),
            (
                "mixed-broader",
                dict(case=True, layout=True, warning=True),
                "broader",
                {"M1", "R1"},
            ),
            ("identifier", dict(metadata="urn:example:one"), "broader", {"D1"}),
        ]:
            original = write_book(base / (name + ".epub"), **settings)
            before = inspect(original, name + "-in")
            planned = base / (name + "-plan")
            planned.mkdir()
            candidate = base / (name + "-out.epub")
            plan = repair_rules.plan(original, limits, profile, planned, candidate)
            assert (
                plan.get("built") and {e["rule"] for e in plan["edits"]} == expected
            ), plan
            after = inspect(candidate, name + "-out")
            for data in (before, after):
                assert (
                    data["security"] == {"complete": True, "findings": []}
                    and data["quality"]["complete"]
                ), data
            reason, paired = repair.accept(before, after, None, plan["edits"])
            assert reason is None and len(paired) == len(plan["edits"]), (
                reason,
                paired,
            )
            codes = lambda r: {f["code"] for f in r["quality"]["findings"]}
            assert codes(after) < codes(before), (before, after)
            assert ("broken_navigation_target" in codes(after)) == (
                name == "mixed-mechanical"
            )
            assert ("suspected_ocr_corruption" in codes(after)) == name.startswith(
                "mixed"
            )
            with ZipFile(original) as az, ZipFile(candidate) as bz:
                assert set(az.namelist()) == set(bz.namelist())
                assert (
                    bz.getinfo("mimetype").header_offset
                    == bz.getinfo("mimetype").compress_type
                    == 0
                )
                for member in az.namelist():
                    ideal = az.read(member)
                    if "R1" in expected and member == "nav.xhtml":
                        ideal = ideal.replace(
                            b'"Text.xhtml#start"', b'"text.xhtml#start"'
                        )
                    if "D1" in expected and member == "book.opf":
                        ideal = ideal.replace(
                            b'unique-identifier="PUB"', b'unique-identifier="pub"'
                        )
                    assert bz.read(member) == ideal, member
            print(
                json.dumps(
                    {
                        "case": name,
                        "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                        "output_sha256": hashlib.sha256(
                            candidate.read_bytes()
                        ).hexdigest(),
                        "edits": plan["edits"],
                        "before": before,
                        "after": after,
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
