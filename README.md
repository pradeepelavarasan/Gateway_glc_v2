# GLC — agent gateway

This repository intentionally starts from a version of the gateway with known security gaps left in place, as a hands-on exercise: find the problems, fix them, and document each fix, so the write-up becomes a reference for anyone hardening an agent application before hosting it in the cloud.

## What GLC is

GLC is a gateway that sits between end users and a set of LLM providers. It does two jobs:

- **LLM routing** — a single API surface (`glc/routing.py`, `glc/providers.py`) that forwards chat requests to whichever backend is configured: Cerebras, Gemini, Groq, NVIDIA, OpenRouter, or GitHub Models. A policy engine (`glc/policy/`) sits in front of every tool call and decides allow/deny before anything is dispatched.
- **Channels** — adapters (`glc/channels/catalogue/`) that let the same gateway talk over Discord, Twilio SMS/Voice, and WhatsApp, plus voice transcription/synthesis (`glc/voice/`). Every inbound message carries a trust level (`owner_paired | user_paired | untrusted`) so the policy engine can reject instructions from untrusted sources.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full trust-boundary breakdown.

## Security hardening for cloud deployment

We're moving this gateway onto Modal so it runs as a container reachable from anywhere, and using that move to close the security gaps this repo starts with (container isolation, scoped credentials, network egress filtering — see `docs/ARCHITECTURE.md`).

### Fixed issues

Below is the list of issues that have been fixed so far. For the full write-up of each — what's the problem, root cause, fix, and how to reproduce — see [`FINDINGS.md`](FINDINGS.md).

| # | Issue | Fix |
|---|-------|-----|
| 1 | Unauthenticated reads (schema, status, providers, capabilities, usage/cost) | `/docs` and `/openapi.json` disabled by default; every route now requires the install token except `/healthz` |
| 2 | SSRF via the image URL resolver | Image URLs are validated before fetch — internal/private/loopback ranges blocked (IPv4 + IPv6), redirects re-checked, connection pinned to the resolved IP, plus an optional host allowlist |
| 3 | Verbose upstream errors | Provider failures return a generic message to the client; the raw upstream detail (provider, endpoint, response body) is kept in server-side logs only |
| 4 | Provider keys readable by any in-process code | Keys isolated in a separate broker container; the gateway holds none and delegates each call via a short-lived, provider-scoped capability token |
| 5 | Audit log erasable by in-process code | Audit log is hash-chained with a tail anchor; any edit, deletion, or full wipe is detected by `verify_chain()` |
| 6 | Install token stored in a readable file | Token taken from an injected Secret (gateway-only) and never written to disk, so in-process code can't read it from a file |
| 7 | In-process access to gateway internals (escalate / self-kill / forge ledger) | Requires process/container isolation between the gateway core and adapter/tool code — documented; a shared process can't prevent these in code |

## Run it locally

This is a `uv` project.

```sh
uv sync
uv run glc serve        # gateway on http://localhost:8111
```

Every route except `/healthz` requires the per-installation token, generated on first boot at `$GLC_CONFIG_DIR/install_token` (`~/.glc/install_token` by default):

```sh
curl -H "Authorization: Bearer $(cat ~/.glc/install_token)" localhost:8111/v1/providers
```

## Deploy it on Modal

The gateway ships with a Modal wrapper (`modal_app.py`) that deploys two isolated containers: a **broker** that holds the provider keys, and the public **gateway**, which holds none (see Fixed issue #4). Use mock keys only — never put real provider keys on Modal.

```sh
# one-time: authenticate the CLI with your Modal account
uv run modal token new

# one-time: the provider keys — mounted only into the broker container. Mock values.
uv run modal secret create glc-llm-keys \
  CEREBRAS_API_KEY=mock-cerebras-key \
  GEMINI_API_KEY=mock-gemini-key \
  GITHUB_ACCESS_TOKEN=mock-github-token \
  GROQ_API_KEY=mock-groq-key \
  NVIDIA_API_KEY=mock-nvidia-key \
  OPEN_ROUTER_API_KEY=mock-openrouter-key

# one-time: the broker-signing key the gateway uses to mint capability tokens
uv run modal secret create glc-broker-sign \
  GLC_BROKER_SIGN_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# one-time: the install/control token, bound as a Secret so it's never a readable file
uv run modal secret create glc-install-token \
  GLC_INSTALL_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# deploy (the data volume is created automatically on first deploy)
uv run modal deploy modal_app.py

# confirm it's live
curl <deployment-url>/healthz

# confirm the isolation: the gateway container holds no provider keys
uv run modal run modal_app.py::check_gateway_env

# confirm the in-process fixes: no token file, and a tampered audit log is detected
uv run modal run modal_app.py::check_inprocess_fixes
```

The deployment scales to zero when idle, so it stays free-tier by default.

## License

MIT, see [`LICENSE`](LICENSE).
