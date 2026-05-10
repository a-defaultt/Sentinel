"""
Ingestion Module for Project Sentinel.
Handles reading, filtering, and aggregating Wazuh alerts from JSONL files.
"""
import json
import pandas as pd
import logging
from typing import List, Optional
from config import ALERTS_JSON_PATH, MIN_RULE_LEVEL, logger

class WazuhIngestor:
    def __init__(self, file_path: str = str(ALERTS_JSON_PATH)):
        self.file_path = file_path

    def read_alerts(self) -> pd.DataFrame:
        """Reads Wazuh alerts from a JSONL file and returns a DataFrame."""
        alerts = []
        try:
            logger.info(f"Reading alerts from {self.file_path}")
            with open(self.file_path, 'r') as f:
                for line in f:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to decode JSON line: {e}")
                        continue
            
            if not alerts:
                logger.info("No alerts found in file.")
                return pd.DataFrame()
            
            df = pd.json_normalize(alerts)
            return df
        except FileNotFoundError:
            logger.error(f"Alerts file not found at {self.file_path}")
            return pd.DataFrame()
        except Exception as e:
            logger.error(f"Unexpected error reading alerts: {e}", exc_info=True)
            return pd.DataFrame()

    def filter_and_extract(self, df: pd.DataFrame) -> pd.DataFrame:
        """Filters alerts by level and extracts required fields."""
        if df.empty:
            return df

        # Filter by rule level
        if 'rule.level' in df.columns:
            df = df[df['rule.level'] >= MIN_RULE_LEVEL].copy()
            logger.info(f"Filtered alerts: {len(df)} alerts with level >= {MIN_RULE_LEVEL}")
        else:
            logger.warning("Column 'rule.level' not found in alerts. Skipping filtering.")
            return pd.DataFrame()

        # Map and extract fields
        # Mapping based on common Wazuh alert structure
        field_mapping = {
            'timestamp': 'timestamp',
            'rule.level': 'level',
            'rule.id': 'rule_id',
            'rule.description': 'description',
            'rule.mitre.id': 'mitre_ids',
            'agent.name': 'agent_name',
            'data.srcip': 'srcip',
            'data.dstuser': 'dstuser',
            'data.hashes': 'hashes',
            'data.service': 'service_abused',
            'data.srcport': 'port',
            'data.vulnerability.cve': 'cve',
            'data.ssh.fingerprint': 'ssh_key_fingerprint'
        }

        # Some fields might be in different places depending on the decoder
        # We'll try to fallback if necessary
        extracted_df = pd.DataFrame()
        for src, target in field_mapping.items():
            if src in df.columns:
                extracted_df[target] = df[src]
            else:
                # Fallback for some common variations
                if target == 'srcip' and 'srcip' in df.columns:
                    extracted_df[target] = df['srcip']
                elif target == 'hashes' and 'syscheck.sha1_after' in df.columns:
                    extracted_df[target] = df['syscheck.sha1_after']
                else:
                    extracted_df[target] = None

        logger.info(f"Extraction complete. {len(extracted_df)} records remaining.")
        return extracted_df

    def aggregate_alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        """Aggregates repeated events by rule_id and srcip."""
        if df.empty:
            return df

        # Ensure srcip is a string for grouping
        df['srcip'] = df['srcip'].fillna('unknown')
        
        # We aggregate by rule_id and srcip
        # For other fields, we take the first occurrence or handle appropriately
        aggregation_logic = {
            'timestamp': 'max', # Latest event time
            'level': 'max',
            'description': 'first',
            'mitre_ids': 'first',
            'agent_name': 'first',
            'dstuser': 'first',
            'hashes': 'first',
            'service_abused': 'first',
            'port': 'first',
            'cve': 'first',
            'ssh_key_fingerprint': 'first'
        }

        # Filter aggregation logic to only include columns that exist
        existing_cols = {col: logic for col, logic in aggregation_logic.items() if col in df.columns}
        
        # Perform aggregation
        # We add a 'count' column
        df['count'] = 1
        
        # Group by rule_id and srcip
        grouped = df.groupby(['rule_id', 'srcip']).agg({
            **existing_cols,
            'count': 'sum'
        }).reset_index()

        logger.info(f"Aggregation complete. Reduced to {len(grouped)} unique events.")
        return grouped

def process_daily_alerts() -> pd.DataFrame:
    """Helper function to run the full ingestion pipeline."""
    ingestor = WazuhIngestor()
    raw_df = ingestor.read_alerts()
    if raw_df.empty:
        return pd.DataFrame()
    
    extracted_df = ingestor.filter_and_extract(raw_df)
    if extracted_df.empty:
        return pd.DataFrame()
    
    aggregated_df = ingestor.aggregate_alerts(extracted_df)
    return aggregated_df

if __name__ == "__main__":
    # Test run
    logging.basicConfig(level=logging.INFO)
    result = process_daily_alerts()
    if not result.empty:
        print(result.head())
    else:
        print("No alerts processed.")
