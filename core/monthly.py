import json
import os
import shutil
import pandas as pd
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from config import DATA_DIR, MONTHLY_DIGEST_PATH, logger
from core.ai_client import NVIDIAClient
from core.dispatch import Dispatcher
from core.memory import SentinelMemory

class MonthlyReporter:
    def __init__(self, ai_client: NVIDIAClient, dispatcher: Dispatcher):
        self.ai_client = ai_client
        self.dispatcher = dispatcher
        self.digest_path = MONTHLY_DIGEST_PATH
        # Memory is needed for cross-month query
        self.memory = SentinelMemory(ai_client)

    def _read_digests(self) -> List[Dict[str, Any]]:
        """Reads all entries from the current monthly digest file."""
        digests = []
        if not self.digest_path.exists():
            return digests

        try:
            with open(self.digest_path, 'r') as f:
                for line in f:
                    try:
                        digests.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error reading monthly digests: {e}")
        
        return digests

    def _compute_aggregates(self, digests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Computes Option B aggregates from daily digests."""
        if not digests:
            return {}

        df = pd.DataFrame(digests)
        
        # MITRE Heatmap
        mitre_list = []
        for tactics in df['top_mitre_tactics']:
            if isinstance(tactics, list):
                mitre_list.extend(tactics)
        
        mitre_heatmap = pd.Series(mitre_list).value_counts().to_dict() if mitre_list else {}
        
        # Top IOCs
        all_iocs = []
        for iocs in df['iocs']:
            if isinstance(iocs, list):
                all_iocs.extend(iocs)
        top_iocs = pd.Series(all_iocs).value_counts().head(10).to_dict() if all_iocs else {}
        
        # Busiest Days
        busiest_days = df.sort_values(by='total_critical_events', ascending=False).head(3)[['date', 'total_critical_events']].to_dict(orient='records')
        
        # Novel IOCs
        novel_iocs = []
        for n_iocs in df.get('novel_iocs', []):
            if isinstance(n_iocs, list):
                novel_iocs.extend(n_iocs)
        novel_iocs = list(set(novel_iocs))

        return {
            "total_events_month": int(df['total_critical_events'].sum()),
            "mitre_heatmap": mitre_heatmap,
            "top_iocs": top_iocs,
            "busiest_days": busiest_days,
            "novel_ioc_list": novel_iocs,
            "days_covered": len(df)
        }

    def _archive_digest(self):
        """Archives the current digest file and starts a new one."""
        if not self.digest_path.exists():
            return

        archive_name = f"monthly_digest_{datetime.now().strftime('%Y-%m')}.jsonl"
        archive_path = DATA_DIR / archive_name
        
        try:
            logger.info(f"Archiving monthly digest to {archive_path}")
            shutil.move(str(self.digest_path), str(archive_path))
            # Create a fresh empty file
            self.digest_path.touch()
        except Exception as e:
            logger.error(f"Failed to archive monthly digest: {e}")

    def run_pipeline(self):
        """Executes the monthly reporting pipeline."""
        logger.info("Starting Monthly Reporting Pipeline...")
        
        digests = self._read_digests()
        if not digests:
            logger.warning("No digests found for the month. Skipping monthly report.")
            return

        # Step 2: Compute Aggregates
        aggregates = self._compute_aggregates(digests)
        
        # Step 3: Cross-month ChromaDB query
        # Using top 3 MITRE tactics as query context
        top_tactics = list(aggregates.get('mitre_heatmap', {}).keys())[:3]
        historical_context = self.memory.query_similar_threats(top_tactics)
        
        # Step 4: Monthly AI Call
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'prompt_monthly.txt')
        try:
            with open(template_path, 'r') as f:
                prompt_template = f.read()
        except FileNotFoundError:
            logger.error(f"Monthly template not found at {template_path}")
            return

        user_prompt = prompt_template.replace('{{monthly_aggregates}}', json.dumps(aggregates, indent=2))
        user_prompt = user_prompt.replace('{{daily_digests}}', json.dumps(digests, indent=2))
        user_prompt = user_prompt.replace('{{historical_context}}', "\n---\n".join(historical_context))

        try:
            logger.info("Generating Monthly AI Report...")
            full_report = self.ai_client.generate_text("You are a Senior Security Architect.", user_prompt)

            # Extract briefing
            briefing = "Monthly Briefing extraction failed."
            if "<briefing>" in full_report and "</briefing>" in full_report:
                briefing = full_report.split("<briefing>")[1].split("</briefing>")[0].strip()

            # Step 5: Dispatch
            subject = f"Project Sentinel Monthly Threat Landscape - {datetime.now().strftime('%Y-%m')}"
            import markdown
            html_report = markdown.markdown(full_report)
            
            self.dispatcher.send_email(subject, html_report)
            self.dispatcher.send_webhook(briefing)

            # Archive
            self._archive_digest()
            
            logger.info("Monthly Pipeline Completed Successfully.")
            
        except Exception as e:
            logger.error(f"Monthly Pipeline Failed: {e}", exc_info=True)

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    try:
        ai = NVIDIAClient()
        disp = Dispatcher()
        reporter = MonthlyReporter(ai, disp)
        # reporter.run_pipeline()
    except Exception as e:
        print(f"Monthly init failed: {e}")
