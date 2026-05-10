"""
Enrichment Module for Project Sentinel.
Integrates with AbuseIPDB and VirusTotal to provide threat intelligence for IOCs.
"""
import time
import requests
import logging
from typing import Dict, Any, List, Optional
from config import (
    VIRUSTOTAL_API_KEY, 
    ABUSEIPDB_API_KEY, 
    VT_REQ_PER_MIN, 
    ABUSEIPDB_DAILY_LIMIT,
    logger
)

class ThreatIntelEnricher:
    def __init__(self):
        self.vt_api_key = VIRUSTOTAL_API_KEY
        self.abuse_api_key = ABUSEIPDB_API_KEY
        self.vt_last_call = 0
        self.vt_min_interval = 60.0 / VT_REQ_PER_MIN if VT_REQ_PER_MIN > 0 else 15.0

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Fetches IP reputation from AbuseIPDB."""
        if not self.abuse_api_key:
            logger.warning("AbuseIPDB API key not set. Skipping IP enrichment.")
            return {}

        if not ip or ip == 'unknown' or ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return {}

        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_api_key
        }

        try:
            logger.info(f"Checking IP reputation: {ip}")
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json().get('data', {})
            
            return {
                'abuse_score': data.get('abuseConfidenceScore'),
                'country': data.get('countryCode'),
                'isp': data.get('isp'),
                'usage_type': data.get('usageType')
            }
        except Exception as e:
            logger.error(f"Error checking AbuseIPDB for {ip}: {e}")
            return {}

    def get_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Fetches hash reputation from VirusTotal."""
        if not self.vt_api_key:
            logger.warning("VirusTotal API key not set. Skipping hash enrichment.")
            return {}

        if not file_hash:
            return {}

        # Rate limiting
        elapsed = time.time() - self.vt_last_call
        if elapsed < self.vt_min_interval:
            time.sleep(self.vt_min_interval - elapsed)

        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {
            'x-apikey': self.vt_api_key
        }

        try:
            logger.info(f"Checking hash reputation: {file_hash}")
            self.vt_last_call = time.time()
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                logger.info(f"Hash {file_hash} not found in VirusTotal.")
                return {'vt_status': 'not_found'}
            
            response.raise_for_status()
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            return {
                'malicious_count': stats.get('malicious', 0),
                'harmless_count': stats.get('harmless', 0),
                'vt_status': 'found'
            }
        except Exception as e:
            logger.error(f"Error checking VirusTotal for {file_hash}: {e}")
            return {}

    def enrich_dataframe(self, df: Any) -> Any:
        """Enriches a pandas DataFrame with threat intelligence."""
        if df.empty:
            return df

        # Unique IPs and Hashes for efficiency
        unique_ips = [ip for ip in df['srcip'].unique() if ip and ip != 'unknown']
        unique_hashes = [h for h in df['hashes'].unique() if h] if 'hashes' in df.columns else []

        ip_cache = {}
        for ip in unique_ips:
            ip_cache[ip] = self.get_ip_reputation(ip)

        hash_cache = {}
        for h in unique_hashes:
            hash_cache[h] = self.get_hash_reputation(h)

        # Map back to dataframe
        df['enrichment_ip'] = df['srcip'].map(ip_cache)
        if 'hashes' in df.columns:
            df['enrichment_hash'] = df['hashes'].map(hash_cache)
        else:
            df['enrichment_hash'] = None

        logger.info("Enrichment complete.")
        return df

if __name__ == "__main__":
    # Test
    import pandas as pd
    logging.basicConfig(level=logging.INFO)
    enricher = ThreatIntelEnricher()
    # Mock data
    test_df = pd.DataFrame({
        'srcip': ['8.8.8.8', 'unknown'],
        'hashes': ['da39a3ee5e6b4b0d3255bfef95601890afd80709', None]
    })
    result = enricher.enrich_dataframe(test_df)
    print(result)
