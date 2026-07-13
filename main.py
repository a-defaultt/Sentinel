"""
Main Orchestrator for Project Sentinel.
Sets up the scheduler and manages the execution of daily and monthly SOC pipelines.
"""
import os
import time
import json
import schedule
import logging
import pandas as pd
import threading
import re
from datetime import datetime
from typing import List, Dict, Any

from config import (
    DAILY_REPORT_TIME, 
    MONTHLY_REPORT_TIME, 
    REPORTS_DIR,
    logger
)
from core.ingestion import process_daily_alerts
from core.enrichment import ThreatIntelEnricher
from core.memory import SentinelMemory
from core.ai_client import NVIDIAClient
from core.dispatch import Dispatcher
from core.digest import DigestManager
from core.monitor import AlertMonitor
from core.response import WazuhResponseManager

class ProjectSentinel:
    def __init__(self):
        self.ai_client = NVIDIAClient()
        self.enricher = ThreatIntelEnricher()
        self.memory = SentinelMemory(self.ai_client)
        self.dispatcher = Dispatcher()
        self.digest_manager = DigestManager(self.ai_client)
        self.monitor = AlertMonitor()
        self.response_manager = WazuhResponseManager()

    @staticmethod
    def _extract_alert_hashes(alert: Dict[str, Any]) -> List[str]:
        """Collects file hashes from the common Wazuh alert locations."""
        hashes = []
        h = alert.get('data', {}).get('hashes')
        if h:
            hashes.append(str(h))
        syscheck = alert.get('syscheck', {})
        for field in ('sha256_after', 'sha1_after', 'md5_after'):
            v = syscheck.get(field)
            if v:
                hashes.append(str(v))
        return hashes

    def start_realtime_monitor(self):
        """Starts the background thread for real-time critical alerting.

        Tails ALL alerts (not just level >= 12): a GridPulse IOC match on a
        low-level alert must still fire immediately, and matched source IPs
        are handed to the SOAR layer (which enforces its own guardrails and
        AUDIT/ENFORCE mode).
        """
        def monitor_loop():
            logger.info("Real-time Monitor Thread Started.")
            gp_iocs = {}
            gp_mtime = 0.0

            # Outer restart loop: the monitor must never die silently
            while True:
                try:
                    for alert in self.monitor.tail_alerts():
                        try:
                            # Reload the IOC cache only when the daily sync
                            # actually refreshed it
                            mtime = self.enricher.sheets_client.cache_mtime()
                            if mtime != gp_mtime:
                                gp_iocs = self.enricher.sheets_client.load_cached_iocs()
                                gp_mtime = mtime
                                logger.info(f"Real-time monitor loaded {len(gp_iocs)} GridPulse IOCs.")

                            level = alert.get('rule', {}).get('level', 0)
                            srcip = alert.get('data', {}).get('srcip')

                            matched_info = None
                            matched_value = None
                            if srcip and srcip in gp_iocs:
                                matched_info, matched_value = gp_iocs[srcip], srcip
                            else:
                                for h in self._extract_alert_hashes(alert):
                                    if h in gp_iocs:
                                        matched_info, matched_value = gp_iocs[h], h
                                        break

                            if level < 12 and matched_info is None:
                                continue

                            desc = alert.get('rule', {}).get('description', 'No description')
                            agent_name = alert.get('agent', {}).get('name', 'N/A')
                            agent_id = alert.get('agent', {}).get('id', '000')

                            briefing = f"**CRITICAL ALERT DETECTED (Level {level})**\n- **Description:** {desc}\n- **Agent:** {agent_name}\n- **Source IP:** {srcip or 'N/A'}"
                            if matched_info is not None:
                                briefing += (
                                    f"\n- **THREAT INTEL MATCH:** {matched_value} "
                                    f"({matched_info.get('type')}) is a known indicator "
                                    f"from GridPulse (source: {matched_info.get('source')})"
                                )
                            self.dispatcher.send_webhook(briefing)

                            # SOAR: only IP-type matches on the alert's srcip are
                            # actionable; execute_action applies the guardrails
                            if matched_info is not None and matched_info.get('bucket') == 'ip' \
                                    and srcip and matched_value == srcip:
                                self.response_manager.execute_action(
                                    action_type="BLOCK_IP",
                                    target=srcip,
                                    agent_id=agent_id,
                                    reasoning=f"GridPulse IOC match: {srcip} (source: {matched_info.get('source')})"
                                )
                        except Exception as e:
                            logger.error(f"Error in real-time monitor loop: {e}")
                except Exception as e:
                    logger.error(f"Real-time monitor crashed: {e}. Restarting in 30s.", exc_info=True)
                time.sleep(30)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

    def run_daily_pipeline(self, alerts_path: str = None):
        """Executes the full daily SOC pipeline.

        Args:
            alerts_path: Optional alerts file override (used for historical
                batch processing); defaults to the configured ALERTS_JSON_PATH.
        """
        start_time = datetime.now()
        logger.info(f"Starting Daily Pipeline: {start_time}")

        try:
            # Phase 0: Refresh the GridPulse threat intel cache. Best-effort —
            # on failure matching falls back to the previous cache.
            logger.info("PHASE 0: Syncing GridPulse IOC feed from Google Sheets")
            self.enricher.sheets_client.sync_iocs()

            # Phase 1 & 2: Ingestion & Aggregation
            logger.info("PHASE 1: Ingestion & Aggregation")
            df = process_daily_alerts(alerts_path)
            if df.empty:
                logger.info("No critical alerts to process today. Skipping report generation.")
                return

            # Phase 2: IOC Enrichment
            logger.info("PHASE 2: IOC Enrichment")
            df = self.enricher.enrich_dataframe(df)

            # Phase 3: Historical Memory (RAG)
            logger.info("PHASE 3: Historical Memory Retrieval")
            # Collect query terms (top IPs and Descriptions)
            query_terms = df.sort_values(by='count', ascending=False).head(5)['srcip'].tolist()
            query_terms += df.sort_values(by='level', ascending=False).head(3)['description'].tolist()
            
            historical_contexts = self.memory.query_similar_threats(query_terms)
            
            # Store today's alerts in memory for future
            self.memory.store_alerts(df)

            # Phase 4: Context Management (Token-Aware Compression)
            logger.info("PHASE 4: Context Management")
            MAX_ALERT_TOKENS = 40000

            # Core alert data only — enrichment columns are passed to the
            # prompt separately as enrichment_only_df in Phase 5
            alerts_only_df = df[[c for c in df.columns if not c.startswith('enrichment_')]]

            try:
                # 1. Measure and Budget (Using character-based approximation for Llama 3)
                alert_json_str = alerts_only_df.to_json(orient='records', indent=2)
                token_count = len(alert_json_str) // 4
                
                if token_count <= MAX_ALERT_TOKENS:
                    today_json = alert_json_str
                else:
                    logger.warning(f"Context overflow: {token_count} tokens. Applying statistical compression.")
                    
                    # Sort by level descending to keep high priority intact
                    sorted_df = alerts_only_df.sort_values(by='level', ascending=False)
                    
                    # Apply 15% safety buffer to prevent overflow
                    target_rows = int((MAX_ALERT_TOKENS / token_count) * len(sorted_df) * 0.85)
                    target_rows = max(1, min(target_rows, len(sorted_df)))
                    
                    # Keep top N
                    kept_df = sorted_df.iloc[:target_rows]
                    overflow_df = sorted_df.iloc[target_rows:]
                    
                    # 2. Statistical Summary for overflow
                    summary_lines = ["CONTEXT OVERFLOW MITIGATION: The following telemetry was compressed to save space:"]
                    
                    if not overflow_df.empty:
                        stats = overflow_df.groupby(['rule_id', 'description', 'srcip']).size().reset_index(name='count')
                        for _, row in stats.iterrows():
                            summary_lines.append(f"- {row['count']} occurrences of Rule {row['rule_id']} ({row['description']}) from Src IP {row['srcip']}.")
                    
                    today_json = kept_df.to_json(orient='records', indent=2)
                    today_json += "\n\n" + "\n".join(summary_lines)
            
            except Exception as e:
                logger.error(f"Context management failed: {e}. Defaulting to full raw data.", exc_info=True)
                today_json = alerts_only_df.to_json(orient='records', indent=2)

            # Phase 5: AI Report Generation
            logger.info("PHASE 5: AI Report Generation")
            template_path = os.path.join(os.path.dirname(__file__), 'templates', 'prompt_system.txt')
            with open(template_path, 'r') as f:
                system_prompt_template = f.read()

            # Separate core alert data from enrichment data for the prompt
            enrichment_cols = [c for c in df.columns if c.startswith('enrichment_')]
            enrichment_only_df = df[['srcip', 'hashes'] + enrichment_cols]

            enrichment_json = enrichment_only_df.to_json(orient='records', indent=2)
            hist_context_str = "\n---\n".join(historical_contexts) if historical_contexts else "No relevant historical context found."

            user_prompt = system_prompt_template.replace('{{today_alerts}}', today_json)
            user_prompt = user_prompt.replace('{{enrichment_data}}', enrichment_json)
            user_prompt = user_prompt.replace('{{historical_context}}', hist_context_str)

            full_report = self.ai_client.generate_text("You are a Lead SOC Architect.", user_prompt)

            # Phase 5.5: Save Report Locally
            report_filename = f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"
            report_path = REPORTS_DIR / report_filename
            with open(report_path, "w") as f:
                f.write(full_report)
            logger.info(f"Full report saved locally to {report_path}")

            # Extract briefing
            briefing = "Briefing extraction failed."
            if "<briefing>" in full_report and "</briefing>" in full_report:
                briefing = full_report.split("<briefing>")[1].split("</briefing>")[0].strip()

            # Phase 6: Digest Extraction
            logger.info("PHASE 6: Digest Extraction")
            self.digest_manager.extract_and_append(full_report)

            # Phase 7: Dispatch
            logger.info("PHASE 7: Dispatch")
            # Prepare attachments
            attachments = [
                {'filename': f'alerts_{datetime.now().strftime("%Y-%m-%d")}.json', 'content': today_json.encode()},
                {'filename': f'alerts_{datetime.now().strftime("%Y-%m-%d")}.csv', 'content': df.to_csv(index=False).encode()}
            ]
            
            subject = f"Project Sentinel Daily Report - {datetime.now().strftime('%Y-%m-%d')}"
            self.dispatcher.send_email(subject, full_report, attachments)
            self.dispatcher.send_webhook(briefing)

            # Phase 8: SOAR Action Execution
            logger.info("PHASE 8: SOAR Action Execution")
            try:
                # Look for JSON block in markdown, allowing for extra text after the header
                json_match = re.search(r'### AUTOMATED ACTIONS JSON.*?\s+```json\s+(.*?)\s+```', full_report, re.DOTALL)
                if json_match:
                    actions = json.loads(json_match.group(1))
                    for action in actions:
                        self.response_manager.execute_action(
                            action_type=action.get('type'),
                            target=action.get('target'),
                            agent_id=action.get('agent'),
                            reasoning=action.get('reasoning', 'AI Recommended')
                        )
                else:
                    logger.info("No automated actions JSON block found in report.")
            except Exception as e:
                logger.error(f"Failed to parse or execute automated actions JSON: {e}")

            end_time = datetime.now()
            logger.info(f"Daily Pipeline Completed Successfully in {end_time - start_time}")

        except Exception as e:
            logger.error(f"Daily Pipeline Failed: {e}", exc_info=True)

    def run_monthly_pipeline_if_first_day(self):
        """Checks if today is the first of the month and runs the monthly pipeline."""
        # The schedule library does not catch job exceptions — anything
        # escaping this method would kill the main scheduler loop.
        try:
            if datetime.now().day == 1:
                logger.info("First day of the month detected. Starting Monthly Pipeline...")
                # Monthly logic will be implemented in core/monthly.py
                from core.monthly import MonthlyReporter
                reporter = MonthlyReporter(self.ai_client, self.dispatcher)
                reporter.run_pipeline()
            else:
                logger.info("Not the first day of the month. Monthly pipeline skipped.")
        except Exception as e:
            logger.error(f"Monthly Pipeline Failed: {e}", exc_info=True)

def main():
    sentinel = ProjectSentinel()
    
    # Start Real-time Monitor
    sentinel.start_realtime_monitor()

    # Schedule jobs
    schedule.every().day.at(DAILY_REPORT_TIME).do(sentinel.run_daily_pipeline)
    schedule.every().day.at(MONTHLY_REPORT_TIME).do(sentinel.run_monthly_pipeline_if_first_day)

    logger.info(f"Project Sentinel Scheduler Started. Daily: {DAILY_REPORT_TIME}, Monthly: {MONTHLY_REPORT_TIME}")
    
    # Optional: Run immediately for testing if environment variable set
    if os.getenv("RUN_NOW") == "true":
        sentinel.run_daily_pipeline()

    # Touched every tick; the Docker HEALTHCHECK flags the container
    # unhealthy if this file goes stale
    heartbeat_file = os.getenv("HEARTBEAT_FILE", "/tmp/sentinel-heartbeat")

    while True:
        schedule.run_pending()
        try:
            with open(heartbeat_file, 'w') as hb:
                hb.write(str(datetime.now()))
        except OSError:
            pass
        time.sleep(30)

if __name__ == "__main__":
    main()
