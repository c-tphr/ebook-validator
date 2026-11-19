"""Run the production behavioral gate on benign EPUBs on an isolated Linux system."""

import argparse
from collections import Counter
import hashlib
import json
import socket
from pathlib import Path
import tempfile

from acceptance.v4_books import make_book
from epub_triage.behavior import Behavior
from epub_triage.cli import DEFAULT_LIMITS
from epub_triage.state import State


def summarize(evidence):
    readers = {}
    for engine, run in evidence["engines"].items():
        events = run["events"]
        readers[engine] = dict(
            complete=run["complete"],
            steps=run["steps"],
            gaps=run["gaps"],
            external_links_unactivated=run.get("external_links_unactivated"),
            event_counts=dict(Counter(e["attribution"] for e in events)),
            attributable=[e for e in events if e["attribution"] == "book"],
            comparison="comparison" in run,
            monitor=run.get("monitor"),
        )
    return dict(
        outcome=evidence["outcome"],
        sha256=evidence["sha256"],
        configuration_id=evidence["configuration_id"],
        readers=readers,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--case",
        action="append",
        choices=["clean", "missing", "network", "file", "fixed-layout", "css"],
    )
    options = parser.parse_args()
    with tempfile.TemporaryDirectory() as t, socket.socket() as canary:
        root = Path(t)
        canary.bind(("127.0.0.1", 0))
        canary.listen(4)
        canary.setblocking(False)
        external_image = (
            f"http://127.0.0.1:{canary.getsockname()[1]}/cover?token=sensitive-canary"
        )
        marker = root / "host-only-marker.png"
        marker.write_bytes(b"synthetic canary")
        books = root / "books"
        config = dict(
            queue=root / "results.sqlite",
            folder=books,
            behavior_timeout=options.timeout,
        )
        if options.packages:
            config["behavior_python_packages"] = options.packages
        with State(config, books, None, False, root) as state:
            gate = Behavior(state, root, {k: v[0] for k, v in DEFAULT_LIMITS.items()})
            gate.preflight()
            print(json.dumps(dict(health=gate.configuration["engines"])), flush=True)
            failures = []
            for label, kw, outcome in (
                ("clean", {}, "release"),
                ("missing", dict(missing=True), "hold"),
                ("network", dict(image=external_image), "quarantine"),
                ("file", dict(image=marker.as_uri()), "quarantine"),
                ("fixed-layout", dict(fixed=True), "hold"),
                ("css", dict(background=True), "quarantine"),
            ):
                if options.case and label not in options.case:
                    continue
                book = make_book(books / (label + ".epub"), **kw)
                original = book.read_bytes()
                sha = hashlib.sha256(original).hexdigest()
                r = gate.assess(book, sha)
                report = summarize(r)
                print(json.dumps(dict(case=label, **report)), flush=True)
                if r["outcome"] != outcome or book.read_bytes() != original:
                    failures.append(label)
                if any(
                    word in json.dumps(r)
                    for word in ("sensitive-canary", "unselected-citation")
                ):
                    failures.append(label + "-redaction")
                if label == "clean":
                    if any(
                        reader["external_links_unactivated"] != 1
                        or not reader["complete"]
                        or not any(
                            s.get("fragment") == "note"
                            and s["status"] == "completed"
                            and s.get("pages")
                            for s in reader["steps"]
                        )
                        for reader in report["readers"].values()
                    ):
                        failures.append(label + "-coverage")
                    if not gate.assess(book, sha)["reused"]:
                        failures.append(label + "-reuse")
                if label == "css":
                    events = r["engines"]["weasyprint"]["events"]
                    if not any(
                        e["action"] == "outbound_request" and e["attribution"] == "book"
                        for e in events
                    ):
                        failures.append("CSS resource attribution")
                if label in {"network", "file"}:
                    kind = (
                        "outbound_request" if label == "network" else "out_of_book_read"
                    )
                    for engine, run in r["engines"].items():
                        if not any(
                            e["action"] == kind
                            and e["attribution"] == "book"
                            and e["blocked"]
                            and run["steps"][e["step"]]["member"] == "text.xhtml"
                            for e in run["events"]
                        ):
                            failures.append(label + "-" + engine + "-attribution")
            try:
                connection, _ = canary.accept()
            except BlockingIOError:
                print("PASS host loopback canary received zero connections", flush=True)
            else:
                connection.close()
                failures.append("host loopback received a connection")
            if failures:
                raise SystemExit("Failed live checks: " + ", ".join(failures))
            print(
                "PASS live readers, paired itinerary, blocked book resources, skipped coverage and reuse",
                flush=True,
            )


if __name__ == "__main__":
    main()
