"""Exercise both native CLI adapters as primary and secondary on an isolated Linux host.

The two provider endpoints are local Luna fixtures. Production command dispatch,
Bubblewrap, relay, member policy, SQLite and approval checks run. Scanner and
EPUBCheck verdicts in this repeatable exercise use the benign fixture backend.
"""

import argparse
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
from unittest.mock import patch

from acceptance import model_fixtures as fixture
from acceptance.test_v3_review import Workflow, book


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    args = parser.parse_args()
    service = ThreadingHTTPServer(("127.0.0.1", 0), fixture.Handler)
    service.fixture_counts = {}
    server_thread = threading.Thread(target=service.serve_forever, daemon=True)
    server_thread.start()
    url = f"http://127.0.0.1:{service.server_port}"
    real = fixture.fixture_response
    requests = []

    def observed(provider, request, **kw):
        assert not request.get("tools"), "native tools advertised"
        data = fixture._review_input(fixture._request_text(provider, request))
        assert data and data["finding"]["member"] == "text.xhtml", data
        requests.append((provider, data))
        if os.environ.get("EPUB_TRIAGE_FIXTURE_SCENARIO") == "usage-limit-after-one":
            return real(provider, request, scenario="uncertain")
        scenario = "diagnostic" if provider == "anthropic" else "search"
        return real(provider, request, scenario=scenario)

    case = Workflow()
    case.setUp()
    try:
        with case.cfg.open("a") as target:
            for provider in ("codex", "claude"):
                path = getattr(args, provider).resolve(strict=True)
                target.write(f"{provider}_executable={json.dumps(str(path))}\n")
            target.write(
                'codex_model="gpt-5.4"\nclaude_model="claude-sonnet-4-6"\nreview_timeout=180\n'
            )
        with patch.dict(
            os.environ,
            OPENAI_API_KEY="dummy",
            ANTHROPIC_API_KEY="dummy",
            OPENAI_BASE_URL=url + "/v1",
            ANTHROPIC_BASE_URL=url,
        ), patch.object(fixture, "fixture_response", observed):
            for primary in ["codex", "claude"]:
                name = f"{primary}.epub"
                p = book(case.books / name)
                expected_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                before = len(requests)
                case.invoke("scan", name, expected=1)
                assert len(requests) == before
                first = case.primary(name, primary)
                _, rows, _ = case.invoke("review-second", first["id"], expected=0)
                combined = rows[-1]
                first, second = combined["assessments"]
                assert (
                    first["reviewer"] == primary
                    and first["reviewer"] != second["reviewer"]
                )
                assert first["diff"]["added"] != second["diff"]["added"]
                assert first["diff"]["start"] == second["diff"]["start"]
                assert len(requests) == before + 4, requests[before:]
                assert all(
                    data["book_sha256"] == expected_hash
                    for _, data in requests[before:]
                )
                fresh = requests[before + 2][1]
                assert not fresh["history"] and first["proposal_id"] not in json.dumps(
                    fresh
                )
                assert first["rationale"] not in json.dumps(fresh)
                for a in (first, second):
                    result = a["diagnostics"][0]["result"]
                    assert result.get("matches") or "counts" in result, result
                chosen = case.decide(combined, 1)
                assert chosen["status"] == "published"
                print(
                    json.dumps(
                        dict(
                            book=name,
                            sha256=expected_hash,
                            primary=primary,
                            independent_secondary=second["reviewer"],
                            proposals=[a["diff"] for a in (first, second)],
                            diagnostics=[
                                a["diagnostics"][0]["request"]["action"]
                                for a in (first, second)
                            ],
                            output_sha256=chosen["publication"]["output_sha256"],
                            provider_requests=len(requests) - before,
                            native_tools_advertised=False,
                        )
                    ),
                    flush=True,
                )
            for name in ("quota-a.epub", "quota-b.epub", "quota-c.epub"):
                book(case.books / name)
                case.invoke("scan", name, expected=1)
            service.fixture_counts.clear()
            with patch.dict(
                os.environ, EPUB_TRIAGE_FIXTURE_SCENARIO="usage-limit-after-one"
            ):
                _, paused, _ = case.invoke(
                    "review",
                    "--batch",
                    "--limit",
                    "2",
                    "--reviewer",
                    "codex",
                    expected=2,
                )
            done = [item["id"] for item in paused if item.get("status") == "reviewed"]
            assert len(done) == 1 and any(
                item.get("status") == "paused" for item in paused
            ), paused
            _, state, _ = case.invoke("review-list", expected=0)
            assert sum(row["status"] == "pending" for row in state) == 2, state
            prior = len(requests)
            case.invoke("review", "--batch", "--reviewer", "claude", expected=2)
            assert len(requests) == prior
            _, resumed, _ = case.invoke(
                "review", "--batch", "--reviewer", "codex", "--limit", "1", expected=0
            )
            resumed_ids = [
                row["id"] for row in resumed if row.get("status") == "reviewed"
            ]
            assert len(resumed_ids) == 1 and resumed_ids != done, resumed
            _, after, _ = case.invoke("review-list", expected=0)
            assert sum(row["status"] == "pending" for row in after) == 1, after
            print(
                json.dumps(
                    dict(
                        quota="HTTP 429", completed=done, resumed=resumed_ids, pending=1
                    )
                ),
                flush=True,
            )
    finally:
        case.doCleanups()
        service.shutdown()
        service.server_close()
        server_thread.join()


if __name__ == "__main__":
    main()
