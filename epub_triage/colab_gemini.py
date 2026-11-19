"""Agy-only Gemini request validation and a no-secret localhost compatibility probe."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
import hmac
import json
import re
from socketserver import ThreadingUnixStreamServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from .review_cli import MAX_WIRE, NoRedirect, ReviewerUnavailable

MODEL = re.compile(r"gemini-[a-z0-9._-]{1,100}\Z")
SCHEMA = {"type": "object", "properties": {
    "action": {"type": "string"}, "outcome": {"type": "string"}, "rationale": {"type": "string"},
    "evidence": {"type": "array", "items": {"type": "string"}},
    "edit": {"type": "object", "properties": {
        "member": {"type": "string"}, "start": {"type": "integer"},
        "before": {"type": "string"}, "after": {"type": "string"}}},
    "start": {"type": "integer"}, "member": {"type": "string"}, "query": {"type": "string"},
    "after": {"type": "array", "items": {}}, "name": {"type": "string"},
    "terms": {"type": "array", "items": {"type": "string"}},
}, "required": ["action"]}


def parts(value):
    if not isinstance(value, dict) or set(value) - {"role", "parts"} or value.get("role") not in {
            None, "user", "model"}:
        raise ValueError("Gemini requested a non-text content role.")
    sequence = value.get("parts")
    if not isinstance(sequence, list) or not sequence or not all(isinstance(item, dict) and
            set(item) == {"text"} and isinstance(item["text"], str) for item in sequence):
        raise ValueError("Gemini requested a non-text content part.")
    return value


def messages_only(data):
    if not isinstance(data, dict) or not isinstance(data.get("contents"), list) or not data["contents"]:
        raise ValueError("Invalid Gemini content.")
    for field in ("tools", "toolConfig", "tool_config", "functionDeclarations", "function_declarations"):
        if data.get(field):
            raise ValueError("Gemini attempted to register or configure a native tool.")
    output = {"contents": [parts(item) for item in data["contents"]]}
    system = data.get("systemInstruction") or data.get("system_instruction")
    if system:
        output["systemInstruction"] = parts(system)
    output["generationConfig"] = {"responseMimeType": "application/json", "responseJsonSchema": SCHEMA,
                                  "maxOutputTokens": 4096, "candidateCount": 1}
    return output


def validate_result(data):
    output = data.get("candidates")
    if output is None and ("usageMetadata" in data or "promptFeedback" in data):
        return
    if not isinstance(output, list) or not output:
        raise ValueError("Gemini response has no candidates.")
    for candidate in output:
        if not isinstance(candidate, dict):
            raise ValueError("Invalid Gemini candidate.")
        content = candidate.get("content")
        if content is not None:
            parts(content)


def validate_response(data, media):
    if media == "application/json":
        validate_result(json.loads(data))
    elif media == "text/event-stream":
        count = 0
        for line in data.splitlines():
            if line.startswith(b"data:"):
                validate_result(json.loads(line[5:].strip()))
                count += 1
        if not count:
            raise ValueError("Incomplete Gemini stream.")
    else:
        raise ValueError("Unexpected Gemini response content type.")


@contextmanager
def wire(endpoint, *, ticket, model, credential=None, marker=None):
    if not MODEL.fullmatch(model or ""):
        raise ReviewerUnavailable("Set a specific supported Gemini model ID.")
    if bool(credential) == bool(marker):
        raise ValueError("Gemini relay needs either a probe marker or a credential.")
    route = "/v1beta/models/" + model
    opener = build_opener(ProxyHandler({}), NoRedirect())
    errors = []
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            from urllib.parse import parse_qs, urlsplit
            self.connection.settimeout(90)
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            supplied = self.headers.get("x-goog-api-key") or "".join(query.pop("key", ()))
            if (not hmac.compare_digest(supplied, ticket) or
                    (parsed.path, query) not in ((route + ":generateContent", {}),
                                                 (route + ":streamGenerateContent", {"alt": ["sse"]}))):
                self.send_error(403)
                return
            headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
            try:
                length = int(self.headers.get("Content-Length", -1))
                if not 0 < length <= MAX_WIRE:
                    raise ValueError("Gemini request exceeds the limit.")
                payload = messages_only(json.loads(self.rfile.read(length)))
                path = parsed.path + ("?alt=sse" if query else "")
                if marker:
                    hits.append(True)
                    response = {"candidates": [{"content": {"role": "model", "parts": [{"text":
                        json.dumps({"action": "assess", "outcome": "uncertain", "rationale": marker,
                                    "evidence": ["Public provider transport control"]})}]}, "finishReason": "STOP"}]}
                    contents = json.dumps(response).encode()
                    media = "application/json"
                    if query:
                        contents = b"data: " + contents + b"\n\n"
                        media = "text/event-stream"
                else:
                    headers["x-goog-api-key"] = credential
                    request = Request("https://generativelanguage.googleapis.com" + path,
                                      json.dumps(payload).encode(), headers)
                    with opener.open(request, timeout=90) as upstream:
                        media = upstream.headers.get_content_type()
                        contents = upstream.read(MAX_WIRE + 1)
                    if len(contents) > MAX_WIRE:
                        raise ValueError("Gemini response exceeds the limit.")
                    validate_response(contents, media)
            except (HTTPError, OSError, ValueError, TypeError, AttributeError):
                errors.append(True)
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(contents)))
            self.end_headers()
            self.wfile.write(contents)

    with ThreadingUnixStreamServer(str(endpoint), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .1}, daemon=True)
        thread.start()
        try:
            yield errors, hits
        finally:
            server.shutdown()
            thread.join()
