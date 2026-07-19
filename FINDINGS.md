# Findings

Each entry below documents one security finding against this gateway: the invariant it broke, and the fix that closes it, with before/after evidence. See the [README](README.md) for a summary table and how to run the gateway.

---

## 1. Unauthenticated reads and actions (full route map, config disclosure, LLM abuse)

#### Invariant broken
Nothing on the gateway should be reachable — or even discoverable — without the per-installation token. A stranger with only the URL should learn nothing about what routes exist, and should not be able to act on any of them.

#### What's the problem?
- **1.1 — Recon: full route map** — the OpenAPI schema (`/openapi.json`) and interactive docs (`/docs`) were served publicly, giving anyone who found the URL a full blueprint of every route, method, and schema before sending a single real request.
- **1.2 — Config disclosure** (`/v1/status`, `/v1/providers`, `/v1/capabilities`) — these read endpoints answered with no authentication, revealing the provider order, the model behind each provider, and the exact `rpm`/`rpd`/`tpm` rate limits.
- **1.3 — Unauthenticated LLM abuse** (`/v1/chat`) — the chat endpoint itself accepted requests from anyone with no token at all, so a stranger could run up LLM provider usage and cost with no credential.
- **1.4 — Usage and cost read** (`/v1/cost/by_agent`, `/v1/calls`) — usage and per-agent cost data was readable with no auth; empty on a fresh deploy, but it exposes activity once the gateway is in use.

One before-fix capture stands in as the example for all four: the full, unauthenticated `/openapi.json` response below lists `/v1/chat`, `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent`, and `/v1/calls` right alongside every other route, method, and schema — confirming none of them needed a token at the time.

![Unauthenticated /openapi.json response before the fix](assets/screenshots/1_issue.png)

#### Root cause
All four trace back to the same human oversight: only two route groups (the control plane and the channel websocket handshake) were ever given a per-installation token check. The schema, the config reads, the chat endpoint, and the usage/cost reads were written before there was any gateway-wide authentication to fall back on, so nobody added a check to them individually.

#### Solution
One fix closes all four, since it applies to every route rather than each one individually:
- **1.1 — Recon: full route map** — `docs_url`, `redoc_url`, and `openapi_url` now only register when `GLC_ENABLE_DOCS=1` is explicitly set. Deployments don't set it, so those routes don't exist at all — a request gets a plain `404`, not even a `401` that would confirm something's there.
- **1.2–1.4 — Config disclosure, unauthenticated LLM abuse, and usage/cost read** — one middleware now requires `Authorization: Bearer <install-token>` on every HTTP request except `/healthz`, instead of leaving auth to be remembered route-by-route. It reuses the same per-installation token already generated for the control plane and channel adapters, and covers `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/chat`, `/v1/cost/by_agent`, and `/v1/calls` along with everything else.
- Files touched: `glc/main.py`, `tests/conftest.py`, `tests/test_control_plane.py`.

Proof after the fix, captured against the live deployment — one per sub-issue:

**1.1 — `/openapi.json` / `/docs`** are no longer served; an unauthenticated request is rejected:

![Unauthenticated request to /openapi.json now rejected](assets/screenshots/1_fixed.png)

**1.2 — config read (`/v1/status`)** now requires the token:

![Unauthenticated request to /v1/status now rejected](assets/screenshots/1_fixed_2.png)

Authenticated callers still get through, confirming the fix didn't break legitimate use:

```sh
GATEWAY_URL="https://pradeep-elavarasan--glc-v1-gateway-fastapi-app.modal.run"

curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <install-token>" "$GATEWAY_URL/v1/status"       # 200
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <install-token>" "$GATEWAY_URL/v1/providers"    # 200
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <install-token>" "$GATEWAY_URL/v1/capabilities" # 200
```

**1.3 — chat (`/v1/chat`)** rejects an unauthenticated request before it reaches any provider:

```console
$ curl -s -X POST "https://pradeep-elavarasan--glc-v1-gateway-fastapi-app.modal.run/v1/chat" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'
{"detail":"missing bearer token (Authorization: Bearer <install_token>)"}
```

**1.4 — usage/cost read (`/v1/cost/by_agent`)** rejects an unauthenticated read:

```console
$ curl -s "https://pradeep-elavarasan--glc-v1-gateway-fastapi-app.modal.run/v1/cost/by_agent"
{"detail":"missing bearer token (Authorization: Bearer <install_token>)"}
```

**1.5 — Control plane (reference, already gated — nothing to fix)** — the control plane (`/v1/control/*`) already required the install token before this fix; it's the model the data-plane fix (1.1–1.4) now matches. Shown here as the contrast between a guarded and a (previously) unguarded endpoint:

```console
$ curl -s "https://pradeep-elavarasan--glc-v1-gateway-fastapi-app.modal.run/v1/control/presence"
{"detail":"missing bearer token (Authorization: Bearer <install_token>)"}
```

---

## 2. SSRF via the image URL resolver

#### Invariant broken
The gateway must never fetch a caller-supplied URL that points at internal infrastructure. A caller must not be able to use the gateway as a proxy to reach addresses — loopback, private networks, cloud metadata — that they could not reach directly.

#### What's the problem?
Before calling the model, the gateway fetched any `http(s)` image URL supplied in a chat or vision request — server-side, following redirects, with no check on the destination. Two things were wrong:
- **Internal targets were reachable.** A caller could point `image_url` at an internal address (loopback, the cloud-metadata endpoint `169.254.169.254`, private hosts) and the gateway would fetch it on their behalf. Even a URL that looked public could redirect into an internal address and still be followed.
- **There was no way to limit destinations at all.** Beyond internal addresses, the resolver would fetch from *any* host on the public internet, with no notion of an approved list — an unbounded outbound surface (e.g. exfiltrating data to, or pulling arbitrary content from, a server the caller controls).

Reproduced against the live deployment: a probe pointing `image_url` at a caller-controlled `webhook.site` URL was fetched server-side. The webhook logged the incoming request with the gateway's own user-agent (`Mozilla/5.0 (compatible; GLCv1/0.1; +image-resolver)`) — proof the gateway, not the caller, made the outbound request. It failed only later on the mock provider key; the fetch itself was completely unrestricted.

![Chat request pointing image_url at a caller-controlled webhook, before the fix](assets/screenshots/2_issue_1_terminal%20command.png)
![webhook.site logging the gateway's server-side fetch, identified by its GLCv1 user-agent](assets/screenshots/2_issue_webhook%20confirmation.png)

#### Root cause
The image resolver (`glc/routes/chat.py`, `_fetch_to_data_url`) fetched the URL with httpx's automatic redirect following and no validation of the destination at all — neither a check that the host wasn't internal, nor any concept of an approved-destination list. It simply fetched whatever it was handed. Both `/v1/chat` and `/v1/vision` route through this single function, so the gap applied to both.

#### Solution
A new guard (`glc/security/ssrf.py`) validates every URL before it is fetched, and the resolver was rewritten to use it:
- **Block internal ranges (always on).** The host is resolved and rejected if any resolved address is loopback, private, link-local, reserved, multicast, or unspecified — covering IPv4 and IPv6, including IPv4-mapped IPv6. Only `http`/`https` schemes are allowed.
- **Re-check every redirect.** Automatic redirects are disabled; the resolver follows them manually and re-validates each hop, so an allowed public URL can't `302` into an internal address.
- **Connect to the validated IP.** The fetch connects straight to the resolved address (keeping the `Host` header and TLS SNI as the original hostname), so a host can't be flipped to an internal address between validation and fetch (DNS rebinding).
- **Optional host allowlist.** Setting `GLC_IMAGE_URL_ALLOWLIST` to a comma-separated host list restricts the resolver to only those hosts; off by default, so any public host is fetchable while internal ranges stay blocked.
- Files touched: `glc/security/ssrf.py` (new), `glc/routes/chat.py`, `tests/test_ssrf.py` (new).

After the fix — an internal address is refused before any connection is made:

```console
$ curl -s -w "\nHTTP:%{http_code}\n" -X POST "$GATEWAY_URL/v1/chat" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://169.254.169.254/latest/meta-data/"}}]}]}'
{"detail":"blocked image url 'http://169.254.169.254/latest/meta-data/': host '169.254.169.254' resolves to blocked address 169.254.169.254"}
HTTP:400
```

With the optional allowlist enabled (`GLC_IMAGE_URL_ALLOWLIST=google.com,www.google.com`), any host outside the list is refused too — here the same webhook URL from the reproduction:

```console
$ curl -s -w "\nHTTP:%{http_code}\n" -X POST "$GATEWAY_URL/v1/chat" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://webhook.site/e913d306-964d-4a2d-95f7-5fa87a4aac32"}}]}]}'
{"detail":"blocked image url 'https://webhook.site/e913d306-964d-4a2d-95f7-5fa87a4aac32': host 'webhook.site' is not in the image-url allowlist"}
HTTP:400
```

---

## 3. Verbose upstream errors

#### Invariant broken
An error returned to the client must not reveal internal implementation detail — which upstream provider was used, its endpoint, or its raw error response. That detail belongs in server-side logs only.

#### What's the problem?
When an upstream provider call failed, the gateway passed the provider's raw error straight back to the client: the provider name (`gemini`), the upstream HTTP status, the full upstream error body, and the upstream endpoint (`generativelanguage.googleapis.com`). That hands an attacker a free map of the gateway's backends and their infrastructure before probing anything.

```console
$ curl -s -w "\nHTTP:%{http_code}\n" -X POST "$GATEWAY_URL/v1/chat" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'
{"detail":"gemini failed: gemini HTTP 400: {\n  \"error\": {\n    \"code\": 400,\n    \"message\": \"API key not valid. Please pass a valid API key.\",\n    \"status\": \"INVALID_ARGUMENT\",\n    \"details\": [\n      {\n        \"@type\": \"type.googleapis.com/google.rpc.ErrorInfo\",\n        \"reason\": \"API_KEY_INVALID\",\n        \"domain\": \"googleapis.com\",\n        \"metadata\": {\n          \"service\": \"generativelanguage.googleapis.com\"\n        }\n      },\n      {\n   "}
HTTP:502
```

#### Root cause
Several route handlers built their client-facing error by interpolating the raw provider error directly — e.g. `raise HTTPException(502, f"{name} failed: {e}")`. The full detail was already recorded server-side (the audit log), but it was *also* echoed back to the caller. The same pattern was present across `/v1/chat`, `/v1/embed`, `/v1/transcribe`, and `/v1/speak`.

#### Solution
A shared helper (`glc/routes/errors.py`, `upstream_error`) now logs the full upstream detail server-side and returns a generic message to the client. Every upstream-error site across the chat, embed, transcribe, and speak routes was switched to it, so no response names a provider, names an endpoint, or includes a raw upstream body. Client-input errors (malformed base64, unknown provider, oversized input) are left unchanged, since those describe the caller's own request rather than a backend.

- Files touched: `glc/routes/errors.py` (new), `glc/routes/chat.py`, `glc/routes/transcribe.py`, `glc/routes/speak.py`, `tests/test_error_sanitization.py` (new).

After the fix — the same request now gets a generic message with no provider, endpoint, or upstream body:

```console
$ curl -s -w "\nHTTP:%{http_code}\n" -X POST "$GATEWAY_URL/v1/chat" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}'
{"detail":"upstream provider request failed"}
HTTP:502
```

The full detail is still captured, but only in the server-side logs (visible via `modal app logs`):

```text
upstream error [502]: gemini failed: gemini HTTP 400: {... "service": "generativelanguage.googleapis.com" ...}
```

---

## 4. Provider keys readable by any in-process code (dump every provider key)

#### Invariant broken
A provider API key is a gateway-only secret. No component that merely runs *inside* the gateway process — a channel adapter, a voice adapter, a tool — should be able to read it.

#### What's the problem?
Every provider key is injected into the gateway container's environment, and the gateway reads them from `os.environ`. But wrapping the monolith on Modal put the whole gateway — providers, channel adapters, voice adapters, tools — in one container sharing one secret, so any code in the process can read every key straight from `os.environ`. The keys are not isolated from the components that should never hold them.

Reproduced from a fresh checkout (`repro/leak1_provider_keys.py`) — the gateway boots, then a stand-in adapter running in the same process dumps every key (mock values used here; never put real provider keys in a shared environment like this):

```console
$ uv run python repro/leak1_provider_keys.py
[gateway] booted; worker providers loaded: ['cerebras', 'gemini', 'github', 'groq', 'nvidia', 'openrouter']

[adapter] running inside the gateway process — dumping every provider key:
    GEMINI_API_KEY = gmni...   <-- adapter read the gateway's secret
    GROQ_API_KEY = gsk_...   <-- adapter read the gateway's secret
    NVIDIA_API_KEY = nvap...   <-- adapter read the gateway's secret
    CEREBRAS_API_KEY = csk-...   <-- adapter read the gateway's secret
    OPEN_ROUTER_API_KEY = sk-o...   <-- adapter read the gateway's secret
    GITHUB_ACCESS_TOKEN = ghp_...   <-- adapter read the gateway's secret
```

#### Root cause
Provider keys live in `os.environ` for the lifetime of the gateway process, and every adapter shares that process. Move 1 (wrapping the monolith) delivered one container with one shared secret, so the environment that holds the keys is the same environment every component runs in — there is no boundary between "code that makes provider calls" and "code that should never see a key."

#### Solution
Provider keys now live only in an isolated **broker** container. The gateway — and every channel/voice adapter and tool running in it — has **no** provider keys; it holds only a broker-signing secret. Every keyed call (chat, routing, embedding, speech-to-text, text-to-speech) is delegated to the broker: the gateway mints a **short-lived, provider-scoped capability token**, the broker verifies it, makes the one upstream call, and returns the result. This is the "per-slot secret + per-tool credential issuance" the finding calls for — an adapter in the gateway can no longer read a provider key because there is none in its environment.

- `glc/security/capabilities.py` (new) — mint/verify short-lived, provider-scoped HMAC tokens.
- `glc/security/broker.py` (new) — `Broker` with `InProcessBroker` (runs the keyed call where the keys live) and `RemoteBroker` (gateway → broker Modal function, minting a token per call).
- `glc/providers.py` — `ProxyProvider`/`build_proxy_providers`: the gateway builds keyless proxies that delegate to the broker.
- `glc/main.py`, `glc/routes/chat.py`, `glc/routes/transcribe.py`, `glc/routes/speak.py` — route every keyed call through the broker.
- `modal_app.py` — split into `broker_exec` (holds `glc-llm-keys`) and the gateway `fastapi_app` (holds only `glc-broker-sign`, **no** provider keys).
- `tests/test_broker_isolation.py` (new).

After the fix — the same snippet run inside each Modal container. The **gateway** container (where adapters run) has no provider keys; the **broker** container is the only place they exist:

```console
$ modal run modal_app.py::check_gateway_env
[gateway container] provider keys present:
    GEMINI_API_KEY = False
    GROQ_API_KEY = False
    NVIDIA_API_KEY = False
    CEREBRAS_API_KEY = False
    OPEN_ROUTER_API_KEY = False
    GITHUB_ACCESS_TOKEN = False

$ modal run modal_app.py::check_broker_env
[broker container] provider keys present:
    GEMINI_API_KEY = True
    GROQ_API_KEY = True
    ... (keys live only in the broker)
```

The gateway still works — `/v1/chat` on the keyless gateway delegates to the broker and reaches the provider (failing only on the mock key, as before), confirming the isolation didn't break the data plane.

---

> The findings below are **in-process** leaks: not remote/HTTP attacks, but code running inside the gateway's own Python process (a malicious tool, or a compromised in-process adapter). They can't be reproduced with `curl` — the repro runs the snippet in the process. A single harness reproduces them from a fresh checkout: `uv run python repro/leak_inprocess.py`.

## 5. Tamper-evident audit log

#### Invariant broken
The security audit trail must be append-only and tamper-evident — no in-process code should be able to erase or edit history without detection.

#### What's the problem?
`glc/audit/store.py` was "append-only" only at the application layer (the `AuditStore` class exposes no delete). The underlying SQLite file had no integrity protection, so any in-process code opened it directly and wiped the whole history — with no error and no record:

```pycon
>>> import os, sqlite3
>>> p = os.path.join(os.getenv("GLC_CONFIG_DIR","."), "audit.sqlite")
>>> sqlite3.connect(p).execute("SELECT COUNT(*) FROM audit_log").fetchone()
(3,)
>>> con = sqlite3.connect(p); con.execute("DELETE FROM audit_log"); con.commit()
<sqlite3.Cursor object at 0x10335f840>
>>> sqlite3.connect(p).execute("SELECT COUNT(*) FROM audit_log").fetchone()
(0,)
```

#### Root cause
The append-only guarantee lived only in the Python class; the file on disk had no hash-chain and no external anchor, so a direct `DELETE`/`UPDATE` left an empty, trivially-consistent table.

#### Solution
Each row is now **hash-chained** — `row_hash = sha256(prev_hash + row_content)` — and a separate `audit_head` anchor records the expected tail; each head is also emitted to the server log (off-box and append-only on Modal). `verify_chain()` walks the table and flags any edit (row-hash mismatch), mid-sequence deletion (broken link), or full wipe (row count below the anchor). A direct `DELETE` still runs — a shared process can always touch the file — but it is no longer silent: it is **detected**.

- Files touched: `glc/audit/schema.sql`, `glc/audit/store.py`, `tests/test_inprocess_leaks.py`.

After the fix — the same `DELETE` is now caught:

```pycon
>>> from glc.audit import store as audit
>>> audit.verify_chain()          # a healthy chain
{'rows': 3, 'expected': 3, 'ok': True, 'reason': 'chain intact'}
>>> # ... attacker runs DELETE FROM audit_log ...
>>> audit.verify_chain()
{'rows': 0, 'expected': 3, 'ok': False, 'reason': 'row count 0 != expected 3 (rows deleted)'}
```

## 6. Install token stored in a readable file

#### Invariant broken
The control-plane install token is a gateway-only secret; no in-process code should be able to read it and act on the control plane.

#### What's the problem?
`get_or_create_install_token()` (`glc/config.py`) generated the token and wrote it to a file on disk, so any in-process code read it straight off the filesystem:

```pycon
>>> import os
>>> p = os.path.join(os.getenv("GLC_CONFIG_DIR","."), "install_token")
>>> print(open(p).read()[:6] + "...")
uyCUcW...
```

#### Root cause
The token was persisted to a world-in-process-readable file, rather than injected as a secret the way the deployment already handles provider keys.

#### Solution
The token is now taken from an injected Secret (`GLC_INSTALL_TOKEN`) when present, and **never written to disk** in that case. On Modal it is bound as a Secret to the gateway container only, so the file the repro reads does not exist. (Local dev with no Secret still falls back to the on-disk token, so nothing breaks.)

- Files touched: `glc/config.py`, `modal_app.py` (bind `glc-install-token` to the gateway), `tests/test_inprocess_leaks.py`.

After the fix — with the Secret set, the file read fails:

```pycon
>>> import os
>>> p = os.path.join(os.getenv("GLC_CONFIG_DIR","."), "install_token")
>>> open(p).read()
Traceback (most recent call last):
  ...
FileNotFoundError: [Errno 2] No such file or directory: '.../install_token'
```

## 7. In-process access to gateway internals (requires process isolation)

#### Invariant broken
Untrusted in-process code (a tool, a compromised adapter) must not be able to escalate its own trust, kill the gateway, or forge the cost ledger.

#### What's the problem?
Three more in-process leaks share one root and one fix — they cannot be closed by a code patch in a shared interpreter, only by process/container isolation:

- **Escalate to owner** — `glc/security/pairing.py` exposes `force_pair_owner()`, so in-process code grants itself `owner_paired`:
  ```pycon
  >>> from glc.security.pairing import get_pairing_store
  >>> get_pairing_store().force_pair_owner("telegram", "attacker-id", user_handle="me")
  PairingRecord(channel='telegram', channel_user_id='attacker-id', ..., trust_level='owner_paired', ...)
  ```
- **Kill the gateway from inside** — the remote kill is loopback-blocked, but in-process code signals the process directly:
  ```console
  $ python3 -c "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"; echo "exit: $?"
  exit: 143
  ```
- **Poison the cost ledger** — `glc/db.py`'s `log_call()` is callable in-process and validates nothing:
  ```pycon
  >>> import glc.db
  >>> glc.db.log_call(provider="gemini", model="x", input_tokens=999999999, agent="victim")
  ```

#### Root cause
All three are inherent to sharing one Python process and PID: any code can import and call a module's functions (`force_pair_owner`, `log_call`), and a process can signal itself. `force_pair_owner` also cannot simply be removed — it is the legitimate owner-bootstrap used by every channel adapter and 40+ tests.

#### Solution
The genuine fix is process/container isolation: run untrusted adapter and tool code in a separate container (and PID namespace) from the gateway core, so the pairing store, the gateway process itself, and the cost-ledger writer sit behind a boundary that in-process code cannot reach — the same direction as Finding 4's broker split. Concretely: the pairing store and a signed cost-ledger writer move behind that process boundary, and a separate PID namespace stops the self-kill. This is an environmental/architectural layer, not an application patch — a shared process cannot prevent these, so a code change here would not be an honest fix.

<!--
## N. <finding title>

#### Invariant broken
Which security guarantee this violates.

#### What's the problem?
What's wrong and how it could be exploited.

#### Root cause
Why the code ended up this way — the underlying design or assumption that let the problem in.

#### Solution
How we fixed it — what changed, and the file(s) touched. Include before/after screenshots or command output here to show the fix working.
-->
