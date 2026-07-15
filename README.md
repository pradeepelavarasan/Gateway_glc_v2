# GLC — agent gateway

This repository intentionally starts from a version of the gateway with known security gaps left in place, as a hands-on exercise: find the problems, fix them, and document each fix, so the write-up becomes a reference for anyone hardening an agent application before hosting it in the cloud.

## What GLC is

GLC is a gateway that sits between end users and a set of LLM providers. It does two jobs:

- **LLM routing** — a single API surface (`glc/routing.py`, `glc/providers.py`) that forwards chat requests to whichever backend is configured: Cerebras, Gemini, Groq, NVIDIA, OpenRouter, or GitHub Models. A policy engine (`glc/policy/`) sits in front of every tool call and decides allow/deny before anything is dispatched.
- **Channels** — adapters (`glc/channels/catalogue/`) that let the same gateway talk over Discord, Twilio SMS/Voice, and WhatsApp, plus voice transcription/synthesis (`glc/voice/`). Every inbound message carries a trust level (`owner_paired | user_paired | untrusted`) so the policy engine can reject instructions from untrusted sources.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full trust-boundary breakdown.

## Security hardening for cloud deployment

We're moving this gateway onto Modal so it runs as a container reachable from anywhere, and using that move to close the security gaps this repo starts with (container isolation, scoped credentials, network egress filtering — see `docs/ARCHITECTURE.md`). This section is a running log of what's been fixed so far: each entry names the issue, the invariant it broke, and the fix that was shipped.

### Fixed issues

### 1. Public API schema (full route map)

**What's the problem?**
The gateway's OpenAPI schema (`/openapi.json`) and interactive docs (`/docs`) were served publicly with no restrictions. Anyone who found the gateway's URL could pull a complete map of every route, method, and request/response schema — a full blueprint for probing the gateway before sending it a single real request.

**Root cause:**
The FastAPI app was built with framework defaults and never overrode `docs_url`/`redoc_url`/`openapi_url`, so the schema routes were always registered. More broadly, only two route groups (the control plane and the channel websocket handshake) checked for a per-installation token; every other route — including the schema itself — had no authentication at all.

**Solution:**
- The schema/docs routes are now off unless explicitly opted into: `docs_url`, `redoc_url`, and `openapi_url` only register when `GLC_ENABLE_DOCS=1` is set. Deployments don't set it, so those routes don't exist at all — a request gets a plain `404`, not even a `401` that would confirm something's there.
- One middleware now requires `Authorization: Bearer <install-token>` on every HTTP request except `/healthz`, instead of leaving auth to be remembered route-by-route. It reuses the same per-installation token already generated for the control plane and channel adapters.

<!--
### N. <issue title>

**What's the problem?**
What's wrong and how it could be exploited.

**Root cause:**
Why the code ended up this way — the underlying design or assumption that let the problem in.

**Solution:**
How we fixed it — what changed, and the file(s) touched.
-->

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

The gateway ships with a Modal wrapper (`modal_app.py`) that builds the container image, mounts a persistent volume for its databases, and injects provider keys as a secret. Use mock keys only — never put real provider keys on Modal.

```sh
# one-time: authenticate the CLI with your Modal account
uv run modal token new

# one-time: create the secret the wrapper expects, with mock values
uv run modal secret create glc-llm-keys \
  CEREBRAS_API_KEY=mock-cerebras-key \
  GEMINI_API_KEY=mock-gemini-key \
  GITHUB_ACCESS_TOKEN=mock-github-token \
  GROQ_API_KEY=mock-groq-key \
  NVIDIA_API_KEY=mock-nvidia-key \
  OPEN_ROUTER_API_KEY=mock-openrouter-key

# deploy (the data volume is created automatically on first deploy)
uv run modal deploy modal_app.py

# confirm it's live
curl <deployment-url>/healthz
```

The deployment scales to zero when idle, so it stays free-tier by default.

## License

MIT, see [`LICENSE`](LICENSE).
