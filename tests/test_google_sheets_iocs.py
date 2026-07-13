"""
Tests for the GridPulse Google Sheets IOC feed integration.

Unit tests run against a seeded local cache (no network). The live sync
test runs only when real credentials and a sheet ID are configured.

Run: python -m pytest tests/test_google_sheets_iocs.py -v
"""
import json
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import GOOGLE_SHEET_ID, GOOGLE_SHEETS_CREDENTIALS_PATH
from core.google_sheets_client import GoogleSheetsIOCClient

TEST_IP = "185.220.101.42"
TEST_HASH = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


@pytest.fixture
def seeded_client(tmp_path):
    """A client whose cache is seeded with known indicators."""
    cache_file = tmp_path / "gridpulse_ioc_cache.json"
    cache = {
        TEST_IP: {
            "type": "ip_address", "bucket": "ip",
            "source": "Test-Suite", "confidence": "high",
            "malware_family": "", "threat_type": "botnet",
            "added_utc": "2026-07-01 00:00:00",
        },
        TEST_HASH: {
            "type": "sha1", "bucket": "hash",
            "source": "Test-Suite", "confidence": "",
            "malware_family": "TestFam", "threat_type": "",
            "added_utc": "2026-07-01 00:00:00",
        },
    }
    cache_file.write_text(json.dumps(cache))
    return GoogleSheetsIOCClient(cache_file=cache_file)


def test_load_cached_iocs(seeded_client):
    iocs = seeded_client.load_cached_iocs()
    assert len(iocs) == 2
    assert iocs[TEST_IP]["bucket"] == "ip"
    assert iocs[TEST_HASH]["bucket"] == "hash"


def test_missing_cache_returns_empty(tmp_path):
    client = GoogleSheetsIOCClient(cache_file=tmp_path / "nope.json")
    assert client.load_cached_iocs() == {}
    assert client.cache_mtime() == 0.0


def test_enricher_matches_and_escalates(seeded_client, monkeypatch):
    """A cached IOC match must flag the row and raise its level to 15."""
    from core.enrichment import ThreatIntelEnricher

    enricher = ThreatIntelEnricher()
    enricher.sheets_client = seeded_client
    # No live reputation APIs in unit tests
    monkeypatch.setattr(enricher, "get_ip_reputation", lambda ip: {})
    monkeypatch.setattr(enricher, "get_hash_reputation", lambda h: {})

    df = pd.DataFrame({
        "srcip": [TEST_IP, "8.8.8.8", "unknown"],
        "hashes": [None, TEST_HASH, None],
        "rule_id": ["5715", "5716", "5717"],
        "level": [5, 7, 10],
    })
    result = enricher.enrich_dataframe(df)

    ip_row = result[result["srcip"] == TEST_IP].iloc[0]
    assert bool(ip_row["enrichment_gridpulse_match"]) is True
    assert ip_row["enrichment_gridpulse_source"] == "Test-Suite"
    assert int(ip_row["level"]) == 15

    hash_row = result[result["srcip"] == "8.8.8.8"].iloc[0]
    assert bool(hash_row["enrichment_gridpulse_match"]) is True
    assert hash_row["enrichment_gridpulse_type"] == "sha1"
    assert int(hash_row["level"]) == 15

    clean_row = result[result["srcip"] == "unknown"].iloc[0]
    assert bool(clean_row["enrichment_gridpulse_match"]) is False
    assert int(clean_row["level"]) == 10


def test_enricher_survives_empty_cache(tmp_path, monkeypatch):
    """No cache file -> no matches, no crash, columns still present."""
    from core.enrichment import ThreatIntelEnricher

    enricher = ThreatIntelEnricher()
    enricher.sheets_client = GoogleSheetsIOCClient(cache_file=tmp_path / "nope.json")
    monkeypatch.setattr(enricher, "get_ip_reputation", lambda ip: {})
    monkeypatch.setattr(enricher, "get_hash_reputation", lambda h: {})

    df = pd.DataFrame({"srcip": ["8.8.8.8"], "hashes": [None], "rule_id": ["1"], "level": [5]})
    result = enricher.enrich_dataframe(df)
    assert bool(result.iloc[0]["enrichment_gridpulse_match"]) is False
    assert int(result.iloc[0]["level"]) == 5


@pytest.mark.skipif(
    not (GOOGLE_SHEET_ID and GOOGLE_SHEETS_CREDENTIALS_PATH.exists()),
    reason="Live credentials/sheet not configured",
)
def test_live_sync(tmp_path):
    """Integration: pull the real GridPulse sheet into a temp cache."""
    client = GoogleSheetsIOCClient(cache_file=tmp_path / "live_cache.json")
    assert client.sync_iocs() is True
    iocs = client.load_cached_iocs()
    assert isinstance(iocs, dict)
    # Every entry must carry the normalized structure
    for value, info in list(iocs.items())[:10]:
        assert info["type"] and "bucket" in info
    print(f"\n[live] synced {len(iocs)} IOCs from the shared sheet")
