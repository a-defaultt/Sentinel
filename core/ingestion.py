"""
Ingestion Module for Project Sentinel.
Handles reading, filtering, and aggregating Wazuh alerts from JSONL files.
"""
import json
import pandas as pd
import logging
import gzip
import os
from typing import List, Optional, Generator
from config import ALERTS_JSON_PATH, MIN_RULE_LEVEL, logger

class WazuhIngestor:
    def __init__(self, file_path: str = str(ALERTS_JSON_PATH)):
        self.file_path = file_path

    def _get_file_handle(self, file_path: str):
        """Returns a file handle, handling .gz compression automatically."""
        if file_path.endswith('.gz'):
            return gzip.open(file_path, 'rt', encoding='utf-8', errors='replace')
        return open(file_path, 'r', encoding='utf-8', errors='replace')

    def read_alerts(self, chunk_size: int = 5000) -> Generator[pd.DataFrame, None, None]:
        """
        Reads Wazuh alerts in chunks for memory efficiency.
        
        Args:
            chunk_size (int): Number of lines to process per chunk.
        """
        if not os.path.exists(self.file_path):
            logger.error(f"Alerts file not found at {self.file_path}")
            return

        try:
            logger.info(f"Reading alerts in chunks from {self.file_path} (size={chunk_size})")
            with self._get_file_handle(self.file_path) as f:
                chunk = []
                for line in f:
                    try:
                        chunk.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    
                    if len(chunk) >= chunk_size:
                        yield pd.json_normalize(chunk)
                        chunk = []
                
                if chunk:
                    yield pd.json_normalize(chunk)
        except Exception as e:
            logger.error(f"Unexpected error reading alerts: {e}", exc_info=True)

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
            'rule.groups': 'rule_groups',
            'agent.name': 'agent_name',
            'agent.id': 'agent_id',
            'location': 'location',
            'data.srcip': 'srcip',
            'data.dstuser': 'dstuser',
            'data.hashes': 'hashes',
            'data.service': 'service_abused',
            'data.srcport': 'port',
            'data.vulnerability.cve': 'cve',
            'data.ssh.fingerprint': 'ssh_key_fingerprint',
            'full_log': 'full_log',
            'data.parent_id': 'parent_id',
            'data.process_name': 'process_name',
            'data.command': 'command'
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
            'rule_groups': 'first',
            'agent_name': 'first',
            'agent_id': 'first',
            'location': 'first',
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
    """Helper function to run the full ingestion pipeline across all chunks."""
    ingestor = WazuhIngestor()
    all_processed_chunks = []
    
    for chunk_df in ingestor.read_alerts():
        extracted_df = ingestor.filter_and_extract(chunk_df)
        if not extracted_df.empty:
            all_processed_chunks.append(extracted_df)
    
    if not all_processed_chunks:
        return pd.DataFrame()
    
    combined_df = pd.concat(all_processed_chunks, ignore_index=True)
    return ingestor.aggregate_alerts(combined_df)

if __name__ == "__main__":
    # Test run
    logging.basicConfig(level=logging.INFO)
    result = process_daily_alerts()
    if not result.empty:
        print(result.head())
    else:
        print("No alerts processed.")
