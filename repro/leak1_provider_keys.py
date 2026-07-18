"""Repro — leak 1: any code in the gateway process reads every provider key.

Run from a fresh checkout:  uv run python repro/leak1_provider_keys.py

Simulates the deployment: the Modal secret injects provider keys into the
gateway container's environment, the gateway boots and loads its providers,
and then a *different* component loaded into the same process (a channel or
voice adapter, or a tool) reads every key straight from os.environ.
"""

import os

# 1) The Modal secret would inject these into the gateway container's env.
#    Obvious MOCK values here (assignment rule: mock keys only).
MOCK_KEYS = {
    "GEMINI_API_KEY": "gmni-MOCK-9f2a1c7d",
    "GROQ_API_KEY": "gsk_MOCK-8b3e2f",
    "NVIDIA_API_KEY": "nvapi-MOCK-1a2b",
    "CEREBRAS_API_KEY": "csk-MOCK-77xz",
    "OPEN_ROUTER_API_KEY": "sk-or-MOCK-qq10",
    "GITHUB_ACCESS_TOKEN": "ghp_MOCK-abcd12",
}
for _k, _v in MOCK_KEYS.items():
    os.environ[_k] = _v

# 2) The gateway boots and loads its worker providers.
from glc.cache import GeminiCache  # noqa: E402
from glc.providers import build_providers  # noqa: E402

providers = build_providers(GeminiCache(ttl_seconds=1))
print(f"[gateway] booted; worker providers loaded: {sorted(providers)}\n")


# 3) A DIFFERENT component in the same process — standing in for a channel or
#    voice adapter / tool — runs the leak-1 snippet. It has no business holding
#    provider keys, yet it reads every one of them:
def adapter_code():
    print("[adapter] running inside the gateway process — dumping every provider key:")
    for name in MOCK_KEYS:
        value = os.environ.get(name)
        if value:
            print(f"    {name} = {value[:4]}...   <-- adapter read the gateway's secret")


adapter_code()
