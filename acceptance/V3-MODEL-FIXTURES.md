# Local v3 model fixtures

These fixtures emulate only the OpenAI Responses API and Anthropic Messages API
over loopback HTTP. They do not need provider credentials and never make network
requests. Start them from the repository root:

```sh
python -m acceptance.model_fixtures --port 8765
```

Configure the CLI processes with dummy keys and local API bases:

```sh
export OPENAI_API_KEY=local-test OPENAI_BASE_URL=http://127.0.0.1:8765/v1
export ANTHROPIC_API_KEY=local-test ANTHROPIC_BASE_URL=http://127.0.0.1:8765
```

The service implements `POST /v1/responses` and `POST /v1/messages` (including
query strings such as `?beta=true`), returns provider-shaped envelopes with
deterministic token usage, and supports both JSON and streaming SSE responses.
It logs each request path. Select a behavior before starting the service with
`EPUB_TRIAGE_FIXTURE_SCENARIO`:

| Value | Behavior |
| --- | --- |
| `conflict` (default) | Codex proposes `World`; Claude proposes `Word` for the corrupted token. |
| `intentional` | Reports the occurrence as intentional without an edit. |
| `uncertain` | Defers the finding as uncertain. |
| `read`, `search`, `diagnostic` | Returns that structured lookup action once, then provides its assessment on a subsequent request with history. |
| `usage-limit` | Returns HTTP 429 for each request. |
| `usage-limit-after-one` | Completes the first request for each provider, then returns HTTP 429. |

The `fixture_response(provider, request, scenario=...)` function is also
available to acceptance tests without starting the HTTP service. For direct
protocol checks, use `curl` against the loopback endpoints and pass any dummy
`Authorization` / `x-api-key` value; the service does not validate credentials.
