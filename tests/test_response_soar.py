"""
Tests for the SOAR response module (WazuhResponseManager).

Mocked-API unit tests — no live Wazuh needed. Behaviours were verified
against a live Wazuh 4.14.6 manager; these lock them in as regressions.

Run: python -m pytest tests/test_response_soar.py -v
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("CHROMA_DATA_PATH", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.response import WazuhResponseManager


def _ar_body(affected=1, failed=0):
    """Mimics the Wazuh /active-response 200 body."""
    return {
        "data": {
            "total_affected_items": affected,
            "total_failed_items": failed,
            "affected_items": ["002"] if affected else [],
            "failed_items": [],
        },
        "message": "AR command was sent" if affected else "AR command was not sent to any agent",
    }


class _Resp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data if data is not None else _ar_body()

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.local:55000")
    monkeypatch.setenv("WAZUH_API_USER", "u")
    monkeypatch.setenv("WAZUH_API_PASS", "p")
    monkeypatch.setenv("WAZUH_API_VERIFY_SSL", "false")
    monkeypatch.setenv("SOAR_MAX_ACTIONS_PER_HOUR", "2")
    monkeypatch.setenv("SOAR_PROTECTED_IPS", "8.8.4.4")
    monkeypatch.setenv("SOAR_MODE", "ENFORCE")
    monkeypatch.delenv("SOAR_ALLOW_ISOLATE", raising=False)
    return WazuhResponseManager()


def _token(status=200):
    return mock.patch("core.response.requests.get", return_value=_Resp(status, {"data": {"token": "tok"}}))


# --- guardrails (apply in every mode) ---

def test_audit_allows_public_ip_without_api(monkeypatch):
    monkeypatch.setenv("SOAR_MODE", "AUDIT")
    monkeypatch.setenv("WAZUH_API_URL", "https://wazuh.local:55000")
    monkeypatch.setenv("WAZUH_API_USER", "u")
    monkeypatch.setenv("WAZUH_API_PASS", "p")
    m = WazuhResponseManager()
    with mock.patch("core.response.requests.request") as rq, mock.patch("core.response.requests.get") as rg:
        assert m.execute_action("BLOCK_IP", "8.8.8.7", "002", "t") is True
        assert not rq.called and not rg.called


@pytest.mark.parametrize("ip", ["192.168.1.1", "127.0.0.1", "10.0.0.1", "8.8.4.4", "not-an-ip; rm -rf /"])
def test_guardrail_refuses_bad_targets(manager, ip):
    assert manager.execute_action("BLOCK_IP", ip, "002", "t") is False


def test_isolate_requires_optin(manager):
    assert manager.execute_action("ISOLATE_HOST", "002", "002", "t") is False


def test_isolate_unimplemented_even_when_optin(manager, monkeypatch):
    monkeypatch.setenv("SOAR_ALLOW_ISOLATE", "true")
    assert manager.execute_action("ISOLATE_HOST", "002", "002", "t") is False


# --- dispatch mechanics ---

def test_enforce_block_succeeds_and_payload_is_correct(manager):
    with _token(), mock.patch("core.response.requests.request", return_value=_Resp(200)) as rq:
        assert manager.execute_action("BLOCK_IP", "8.8.8.7", "002", "t") is True
        method, url = rq.call_args.args
        body = rq.call_args.kwargs["json"]
        assert method == "PUT" and "active-response?agents_list=002" in url
        assert body["command"] == "!firewall-drop"
        assert body["alert"]["data"]["srcip"] == "8.8.8.7"
        assert "custom" not in body  # 4.14 API rejects this field


def test_http_200_but_zero_affected_is_not_success(manager):
    """Wazuh returns 200 even when it dispatches to no agent."""
    with _token(), mock.patch("core.response.requests.request", return_value=_Resp(200, _ar_body(affected=0))):
        assert manager.execute_action("BLOCK_IP", "8.8.8.7", "000", "t") is False


def test_token_expiry_triggers_reauth(manager):
    with _token() as rg, mock.patch("core.response.requests.request", side_effect=[_Resp(401), _Resp(200)]) as rq:
        assert manager.execute_action("BLOCK_IP", "8.8.8.8", "002", "t") is True
        assert rg.call_count == 2 and rq.call_count == 2


def test_rate_cap(manager):
    with _token(), mock.patch("core.response.requests.request", return_value=_Resp(200)):
        assert manager.execute_action("BLOCK_IP", "8.8.8.9", "002", "t") is True
        assert manager.execute_action("BLOCK_IP", "8.8.8.10", "002", "t") is True
        assert manager.execute_action("BLOCK_IP", "8.8.8.11", "002", "t") is False


def test_api_error_reported_honestly(manager):
    with _token(), mock.patch("core.response.requests.request", return_value=_Resp(500)):
        assert manager.execute_action("BLOCK_IP", "8.8.8.12", "002", "t") is False
