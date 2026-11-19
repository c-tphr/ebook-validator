"""Local, deterministic OpenAI/Anthropic API fixtures for v3 CLI acceptance.

No credentials or external network calls are used. Start with:
    python -m acceptance.model_fixtures --port 8765

Point Codex at http://127.0.0.1:8765/v1 and Claude at
http://127.0.0.1:8765. Set any nonempty dummy API keys. Scenario controls:
EPUB_TRIAGE_FIXTURE_SCENARIO=conflict|intentional|uncertain|read|search|diagnostic|
usage-limit|usage-limit-after-one (default conflict).
"""

from __future__ import annotations

import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


def fixture_response(
    provider: str, request: dict[str, Any], *, scenario: str = "conflict"
) -> str:
    """Return the assistant's protocol payload as a JSON string.

    Codex and Claude deliberately recommend different benign replacements for
    the same damaged token. The `uncertain` scenario exercises a non-edit
    outcome. Read/search/diagnostic requests receive valid action responses.
    """
    if scenario not in {
        "conflict",
        "intentional",
        "uncertain",
        "read",
        "search",
        "diagnostic",
        "usage-limit",
        "usage-limit-after-one",
    }:
        raise ValueError(f"unknown fixture scenario: {scenario}")
    if scenario == "usage-limit":
        raise UsageLimit("controlled local model usage limit")

    prompt = _request_text(provider, request)
    # The v3 prompt includes a marker and one compact JSON record.
    payload = _review_input(prompt)
    if payload is None:
        raise ValueError("fixture request did not include EPUB_TRIAGE_REVIEW_V1 input")
    member = "text.xhtml"
    passage = "Wor���d"
    passage_start = 0
    if payload:
        passage_obj = payload.get("passage")
        if isinstance(passage_obj, dict):
            member = str(passage_obj.get("member", member))
            passage = str(passage_obj.get("text", passage))
            passage_start = int(passage_obj.get("start", 0))
        elif isinstance(passage_obj, str):
            passage = passage_obj
    if scenario in {"read", "search", "diagnostic"} and not payload.get("history"):
        action = {
            "read": {"action": "read", "member": member, "start": passage_start},
            "search": {"action": "search", "query": _damaged_token(passage)},
            "diagnostic": {
                "action": "diagnostic",
                "name": "count_variants",
                "terms": ["World", "Word"],
            },
        }[scenario]
        return json.dumps(action, ensure_ascii=False, separators=(",", ":"))

    if scenario == "intentional":
        result = {
            "action": "assess",
            "outcome": "intentional",
            "rationale": "The unusual spelling appears deliberate in this occurrence; retain it unless the author’s source indicates otherwise.",
            "evidence": [f"{member}: {passage!r}"],
        }
    elif scenario == "uncertain" or not any(ch in passage for ch in ("�", "Wor")):
        result = {
            "action": "assess",
            "outcome": "uncertain",
            "rationale": "The surrounding context does not establish the intended wording; preserve the passage pending source evidence.",
            "evidence": [f"{member}: selected finding passage {passage!r}"],
        }
    else:
        before = _damaged_token(passage)
        # Intentionally conflicting benign interpretations for independent-review checks.
        after = "World" if provider == "openai" else "Word"
        pos = passage_start + (passage.find(before) if before in passage else 0)
        result = {
            "action": "assess",
            "outcome": "edit",
            "rationale": (
                "The replacement restores a plausible word in the damaged passage; verify against the source edition."
                if provider == "openai"
                else "The replacement removes the corruption while preserving the readable word; verify against the source edition."
            ),
            "evidence": [f"{member}: {passage}"],
            "edit": {"member": member, "start": pos, "before": before, "after": after},
        }
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


class UsageLimit(Exception):
    pass


def _request_text(provider: str, request: dict[str, Any]) -> str:
    values = (
        request.get("input", "")
        if provider == "openai"
        else request.get("messages", [])
    )

    def collect(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [part for item in value for part in collect(item)]
        if isinstance(value, dict):
            # Skip non-text metadata such as images and tool schemas.
            parts = []
            for key in ("text", "content", "input_text"):
                if key in value:
                    parts.extend(collect(value[key]))
            return parts
        return []

    return "\n".join(collect(values))


def _review_input(prompt: str) -> dict[str, Any] | None:
    marker = "EPUB_TRIAGE_REVIEW_V1"
    if marker not in prompt:
        return None
    for line in prompt.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
                return value if isinstance(value, dict) else None
            except json.JSONDecodeError:
                continue
    return None


def _damaged_token(passage: str) -> str:
    match = re.search(r"\S*�+\S*", passage)
    if match:
        return match.group(0)
    match = re.search(r"Wor\S*d", passage)
    return match.group(0) if match else passage


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LocalModelFixture/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print("fixture: " + fmt % args, flush=True)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/")
        if path in {"/v1/responses", "/responses"}:
            provider = "openai"
        elif path in {"/v1/messages", "/messages"}:
            provider = "anthropic"
        else:
            self._send(404, {"error": {"message": "unknown local fixture endpoint"}})
            return
        try:
            request = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
            )
            print(
                f"fixture request provider={provider} model={request.get('model', 'unknown')} "
                f"stream={bool(request.get('stream'))} path={path}",
                flush=True,
            )
            scenario = os.environ.get("EPUB_TRIAGE_FIXTURE_SCENARIO", "conflict")
            counts = self.server.fixture_counts
            counts[provider] = counts.get(provider, 0) + 1
            if scenario == "usage-limit-after-one" and counts[provider] > 1:
                raise UsageLimit(
                    "controlled local model usage limit after one completed response"
                )
            content = fixture_response(
                provider,
                request,
                scenario=scenario,
            )
        except UsageLimit as error:
            err = {"type": "rate_limit_error", "message": str(error)}
            self._send(
                429,
                (
                    {"type": "error", "error": err}
                    if provider == "anthropic"
                    else {"error": err}
                ),
            )
            return
        except Exception as error:
            self._send(400, {"error": {"message": str(error)}})
            return
        usage = {"input_tokens": 17, "output_tokens": 13}
        if provider == "openai":
            body = {
                "id": "resp_fixture_0001",
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": request.get("model", "fixture-model"),
                "output": [
                    {
                        "id": "msg_fixture",
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": content}],
                    }
                ],
                "output_text": content,
                "usage": {
                    "input_tokens": usage["input_tokens"],
                    "output_tokens": usage["output_tokens"],
                    "total_tokens": sum(usage.values()),
                },
            }
            if request.get("stream"):
                self._openai_stream(body, content)
                return
        else:
            body = {
                "id": "msg_fixture_0001",
                "type": "message",
                "role": "assistant",
                "model": request.get("model", "fixture-model"),
                "content": [{"type": "text", "text": content}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {
                    "input_tokens": usage["input_tokens"],
                    "output_tokens": usage["output_tokens"],
                },
            }
            if request.get("stream"):
                self._anthropic_stream(body, content)
                return
        self._send(200, body)

    def _sse(self, event: str, value: dict[str, Any]) -> None:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        self.wfile.write(f"event: {event}\ndata: {raw}\n\n".encode("utf-8"))

    def _openai_stream(self, response: dict[str, Any], content: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        output = response["output"][0]
        started = {**response, "status": "in_progress", "output": [], "usage": None}
        pending_item = {
            "id": output["id"],
            "type": "message",
            "role": "assistant",
            "status": "in_progress",
            "content": [],
        }
        self._sse("response.created", {"type": "response.created", "response": started})
        self._sse(
            "response.in_progress",
            {"type": "response.in_progress", "response": started},
        )
        self._sse(
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": pending_item,
            },
        )
        part = output["content"][0]
        self._sse(
            "response.content_part.added",
            {
                "type": "response.content_part.added",
                "item_id": output["id"],
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            },
        )
        self._sse(
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "item_id": output["id"],
                "output_index": 0,
                "content_index": 0,
                "delta": content,
            },
        )
        self._sse(
            "response.output_text.done",
            {
                "type": "response.output_text.done",
                "item_id": output["id"],
                "output_index": 0,
                "content_index": 0,
                "text": content,
            },
        )
        self._sse(
            "response.content_part.done",
            {
                "type": "response.content_part.done",
                "item_id": output["id"],
                "output_index": 0,
                "content_index": 0,
                "part": part,
            },
        )
        self._sse(
            "response.output_item.done",
            {"type": "response.output_item.done", "output_index": 0, "item": output},
        )
        self._sse(
            "response.completed", {"type": "response.completed", "response": response}
        )
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _anthropic_stream(self, message: dict[str, Any], content: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self._sse(
            "message_start",
            {"type": "message_start", "message": {**message, "content": []}},
        )
        self._sse(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
        self._sse("ping", {"type": "ping"})
        self._sse(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": content},
            },
        )
        self._sse("content_block_stop", {"type": "content_block_stop", "index": 0})
        self._sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 13},
            },
        )
        self._sse("message_stop", {"type": "message_stop"})
        self.wfile.flush()

    def _send(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.fixture_counts = {}
    print(
        f"Local model fixtures listening on http://{args.host}:{args.port}", flush=True
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
