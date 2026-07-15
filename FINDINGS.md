# Findings

Each entry below documents one security finding against this gateway: the invariant it broke, and the fix that closes it, with before/after evidence. See the [README](README.md) for a summary table and how to run the gateway.

---

## 1. Public API schema (full route map)

**Invariant broken:**
Nothing on the gateway should be reachable — or even discoverable — without the per-installation token. A stranger with only the URL should learn nothing about what routes exist.

**What's the problem?**
The gateway's OpenAPI schema (`/openapi.json`) and interactive docs (`/docs`) were served publicly with no restrictions. Anyone who found the gateway's URL could pull a complete map of every route, method, and request/response schema — a full blueprint for probing the gateway before sending it a single real request.

Captured against the live deployment, before the fix — the full, unauthenticated `/openapi.json` response, enumerating every route (`/v1/chat`, `/v1/control/kill`, `/v1/transcribe`, ...) and request/response schema:

![Unauthenticated /openapi.json response before the fix](assets/screenshots/1_issue.png)

**Root cause:**
The FastAPI app was built with framework defaults and never overrode `docs_url`/`redoc_url`/`openapi_url`, so the schema routes were always registered. More broadly, only two route groups (the control plane and the channel websocket handshake) checked for a per-installation token; every other route — including the schema itself — had no authentication at all.

**Solution:**
- The schema/docs routes are now off unless explicitly opted into: `docs_url`, `redoc_url`, and `openapi_url` only register when `GLC_ENABLE_DOCS=1` is set. Deployments don't set it, so those routes don't exist at all — a request gets a plain `404`, not even a `401` that would confirm something's there.
- One middleware now requires `Authorization: Bearer <install-token>` on every HTTP request except `/healthz`, instead of leaving auth to be remembered route-by-route. It reuses the same per-installation token already generated for the control plane and channel adapters.
- Files touched: `glc/main.py`, `tests/conftest.py`, `tests/test_control_plane.py`.

Captured against the live deployment, after the fix — the same request now rejected:

![Unauthenticated request to /openapi.json now rejected](assets/screenshots/1_fixed.png)

<!--
## N. <finding title>

**Invariant broken:**
Which security guarantee this violates.

**What's the problem?**
What's wrong and how it could be exploited.

**Root cause:**
Why the code ended up this way — the underlying design or assumption that let the problem in.

**Solution:**
How we fixed it — what changed, and the file(s) touched. Include before/after screenshots or command output here to show the fix working.
-->
