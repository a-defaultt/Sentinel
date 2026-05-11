"""
Main Orchestrator for Project Sentinel.
Sets up the scheduler and manages the execution of daily and monthly SOC pipelines.
"""
import os
import time
import schedule
import logging
import pandas as pd
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

class ProjectSentinel:
    def __init__(self):
        self.ai_client = NVIDIAClient()
        self.enricher = ThreatIntelEnricher()
        self.memory = SentinelMemory(self.ai_client)
        self.dispatcher = Dispatcher()
        self.digest_manager = DigestManager(self.ai_client)

    def run_daily_pipeline(self):
        """Executes the full daily SOC pipeline."""
        start_time = datetime.now()
        logger.info(f"Starting Daily Pipeline: {start_time}")

        try:
            # Phase 1 & 2: Ingestion & Aggregation
            logger.info("PHASE 1: Ingestion & Aggregation")
            df = process_daily_alerts()
            if df.empty:
                logger.info("No critical alerts to process today. Skipping report generation.")
                return

            # Phase 3: IOC Enrichment
            logger.info("PHASE 2: IOC Enrichment")
            df = self.enricher.enrich_dataframe(df)

            # Phase 4: Historical Memory (RAG)
            logger.info("PHASE 3: Historical Memory Retrieval")
            # Collect query terms (top IPs and Descriptions)
            query_terms = df.sort_values(by='count', ascending=False).head(5)['srcip'].tolist()
            query_terms += df.sort_values(by='level', ascending=False).head(3)['description'].tolist()
            
            historical_contexts = self.memory.query_similar_threats(query_terms)
            
            # Store today's alerts in memory for future
            self.memory.store_alerts(df)

            # Phase 5: AI Report Generation
            logger.info("PHASE 4: AI Report Generation")
            template_path = os.path.join(os.path.dirname(__file__), 'templates', 'prompt_system.txt')
            with open(template_path, 'r') as f:
                system_prompt_template = f.read()

            # Separate core alert data from enrichment data for the prompt
            enrichment_cols = [c for c in df.columns if c.startswith('enrichment_')]
            alerts_only_df = df.drop(columns=enrichment_cols)
            enrichment_only_df = df[['srcip', 'hashes'] + enrichment_cols]

            today_json = alerts_only_df.to_json(orient='records', indent=2)
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
            logger.info("PHASE 5: Digest Extraction")
            self.digest_manager.extract_and_append(full_report)

            # Phase 7: Dispatch
            logger.info("PHASE 6: Dispatch")
            # Prepare attachments
            attachments = [
                {'filename': f'alerts_{datetime.now().strftime("%Y-%m-%d")}.json', 'content': today_json.encode()},
                {'filename': f'alerts_{datetime.now().strftime("%Y-%m-%d")}.csv', 'content': df.to_csv(index=False).encode()}
            ]
            
            subject = f"Project Sentinel Daily Report - {datetime.now().strftime('%Y-%m-%d')}"
            self.dispatcher.send_email(subject, full_report, attachments)
            self.dispatcher.send_webhook(briefing)

            end_time = datetime.now()
            logger.info(f"Daily Pipeline Completed Successfully in {end_time - start_time}")

        except Exception as e:
            logger.error(f"Daily Pipeline Failed: {e}", exc_info=True)

    def run_monthly_pipeline_if_first_day(self):
        """Checks if today is the first of the month and runs the monthly pipeline."""
        if datetime.now().day == 1:
            logger.info("First day of the month detected. Starting Monthly Pipeline...")
            # Monthly logic will be implemented in core/monthly.py
            from core.monthly import MonthlyReporter
            reporter = MonthlyReporter(self.ai_client, self.dispatcher)
            reporter.run_pipeline()
        else:
            logger.info("Not the first day of the month. Monthly pipeline skipped.")

def main():
    sentinel = ProjectSentinel()
    
    # Schedule jobs
    schedule.every().day.at(DAILY_REPORT_TIME).do(sentinel.run_daily_pipeline)
    schedule.every().day.at(MONTHLY_REPORT_TIME).do(sentinel.run_monthly_pipeline_if_first_day)

    logger.info(f"Project Sentinel Scheduler Started. Daily: {DAILY_REPORT_TIME}, Monthly: {MONTHLY_REPORT_TIME}")
    
    # Optional: Run immediately for testing if environment variable set
    if os.getenv("RUN_NOW") == "true":
        sentinel.run_daily_pipeline()

    while True:
        schedule.run_pending()
        time.sleep(30)

if __name__ == "__main__":
    main()
