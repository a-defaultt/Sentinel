"""
Google Sheets IOC Client for Project Sentinel.

Consumes the threat intelligence feed that GridPulse publishes to a shared
Google Sheet, caching it locally so lookups cost no API calls and survive
Sheets outages.

Sheet ground truth (written by GridPulse's google_sheets_sync):
- opened by key (GOOGLE_SHEET_ID), worksheet GOOGLE_SHEET_WORKSHEET_NAME
- columns: type, value, source, confidence, malware_family, threat_type,
  mallory_tags, mallory_context, source_article, source_url, added_utc
- type values: ip_address, sha256, sha1, md5, domain

This client is strictly read-only (spreadsheets.readonly scope).
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

import gspread
from google.oauth2.service_account import Credentials

from config import (
    DATA_DIR,
    GOOGLE_SHEET_ID,
    GOOGLE_SHEET_WORKSHEET_NAME,
    GOOGLE_SHEETS_CREDENTIALS_PATH,
    GOOGLE_SHEETS_SYNC_ENABLED,
    logger,
)

# Read-only: Sentinel consumes the feed, it must never be able to write it
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]

CACHE_FILE = DATA_DIR / "gridpulse_ioc_cache.json"

# Normalize GridPulse's type strings into match buckets
_TYPE_BUCKETS = {
    "ip_address": "ip",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "domain": "domain",
    "url": "url",
}


class GoogleSheetsIOCClient:
    def __init__(
        self,
        credentials_path: Path = GOOGLE_SHEETS_CREDENTIALS_PATH,
        sheet_id: str = GOOGLE_SHEET_ID,
        worksheet_name: str = GOOGLE_SHEET_WORKSHEET_NAME,
        cache_file: Path = CACHE_FILE,
    ):
        self.credentials_path = Path(credentials_path)
        self.sheet_id = sheet_id
        self.worksheet_name = worksheet_name
        self.cache_file = Path(cache_file)

    def sync_iocs(self) -> bool:
        """Pulls the latest records from the Google Sheet into the local
        cache. Best-effort: returns False (never raises) so a Sheets outage
        degrades to matching against the previous cache."""
        if not GOOGLE_SHEETS_SYNC_ENABLED:
            logger.info("[GridPulse IOCs] Sync disabled via GOOGLE_SHEETS_SYNC_ENABLED.")
            return False
        if not self.sheet_id:
            logger.warning("[GridPulse IOCs] GOOGLE_SHEET_ID not set. Skipping sync.")
            return False
        if not self.credentials_path.exists():
            logger.error(f"[GridPulse IOCs] Credentials not found at {self.credentials_path}. Skipping sync.")
            return False

        try:
            logger.info(f"[GridPulse IOCs] Syncing from sheet {self.sheet_id[:8]}.../{self.worksheet_name}")
            creds = Credentials.from_service_account_file(str(self.credentials_path), scopes=SCOPES)
            client = gspread.authorize(creds)
            worksheet = client.open_by_key(self.sheet_id).worksheet(self.worksheet_name)
            records = worksheet.get_all_records()

            # Keyed on the raw indicator value for O(1) lookups
            ioc_dict: Dict[str, Dict[str, Any]] = {}
            for r in records:
                val = str(r.get("value") or "").strip()
                typ = str(r.get("type") or "").strip()
                if not val or not typ:
                    continue
                ioc_dict[val] = {
                    "type": typ,
                    "bucket": _TYPE_BUCKETS.get(typ, "other"),
                    "source": r.get("source", "Unknown"),
                    "confidence": r.get("confidence", ""),
                    "malware_family": r.get("malware_family", ""),
                    "threat_type": r.get("threat_type", ""),
                    "added_utc": r.get("added_utc", ""),
                }

            tmp = self.cache_file.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(ioc_dict, f, indent=2)
            os.replace(tmp, self.cache_file)

            logger.info(f"[GridPulse IOCs] Synced {len(ioc_dict)} indicators to local cache.")
            return True
        except Exception as e:
            logger.error(f"[GridPulse IOCs] Sync failed: {e}. Matching will use the previous cache.")
            return False

    def load_cached_iocs(self) -> Dict[str, Dict[str, Any]]:
        """Loads the cached indicator dict; empty dict if no cache yet."""
        if not self.cache_file.exists():
            logger.warning("[GridPulse IOCs] No local cache yet. Run sync_iocs() first.")
            return {}
        try:
            with open(self.cache_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"[GridPulse IOCs] Failed to load cache: {e}")
            return {}

    def cache_mtime(self) -> float:
        """Cache file modification time (0 if absent) — lets long-lived
        consumers reload only when the daily sync actually refreshed it."""
        try:
            return self.cache_file.stat().st_mtime
        except OSError:
            return 0.0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    client = GoogleSheetsIOCClient()
    if client.sync_iocs():
        print(f"Synced {len(client.load_cached_iocs())} IOCs")
