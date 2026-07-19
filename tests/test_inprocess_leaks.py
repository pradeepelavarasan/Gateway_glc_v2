"""In-process leak fixes: hash-chained audit log (leak 2) and install-token
bound as a Secret rather than a readable file (leak 4)."""

from __future__ import annotations

import os
import sqlite3


def _seed_audit(n=3):
    from glc.audit import store as audit

    audit.init_store()
    for i in range(n):
        audit.append(
            channel="telegram", channel_user_id="owner", trust_level="owner_paired",
            event_type="tool_dispatch", tool=f"t{i}",
        )
    return audit


def test_verify_chain_intact_after_appends():
    audit = _seed_audit(3)
    v = audit.verify_chain()
    assert v["ok"] is True and v["rows"] == 3


def test_verify_chain_detects_full_delete():
    audit = _seed_audit(3)
    con = sqlite3.connect(os.environ["GLC_AUDIT_DB"])
    con.execute("DELETE FROM audit_log")
    con.commit()
    con.close()
    v = audit.verify_chain()
    assert v["ok"] is False
    assert v["rows"] == 0 and v["expected"] == 3


def test_verify_chain_detects_row_edit():
    audit = _seed_audit(3)
    con = sqlite3.connect(os.environ["GLC_AUDIT_DB"])
    con.execute("UPDATE audit_log SET tool='tampered' WHERE id=(SELECT MIN(id) FROM audit_log)")
    con.commit()
    con.close()
    v = audit.verify_chain()
    assert v["ok"] is False
    assert "hash mismatch" in v["reason"] or "broken link" in v["reason"]


def test_install_token_from_secret_writes_no_file(monkeypatch):
    from glc.config import get_or_create_install_token, install_token_path

    monkeypatch.setenv("GLC_INSTALL_TOKEN", "secret-token-value")
    assert get_or_create_install_token() == "secret-token-value"
    # The leak-4 repro reads a file; there must be none when the Secret is set.
    assert not install_token_path().exists()


def test_install_token_file_fallback_when_no_secret(monkeypatch):
    from glc.config import get_or_create_install_token, install_token_path

    monkeypatch.delenv("GLC_INSTALL_TOKEN", raising=False)
    tok = get_or_create_install_token()
    assert tok and install_token_path().exists()
