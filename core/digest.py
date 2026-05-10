import json
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set
from config import MONTHLY_DIGEST_PATH, logger
from core.ai_client import NVIDIAClient

class DigestManager:
    def __init__(self, ai_client: NVIDIAClient):
        self.ai_client = ai_client
        self.digest_path = MONTHLY_DIGEST_PATH

    def _get_known_iocs(self, days: int = 7) -> Set[str]:
        """Reads previous digests and collects IOCs from the last N days."""
        known_iocs = set()
        if not self.digest_path.exists():
            return known_iocs

        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            with open(self.digest_path, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        entry_date = datetime.strptime(entry.get('date'), '%Y-%m-%d')
                        if entry_date >= cutoff_date:
                            iocs = entry.get('iocs', [])
                            known_iocs.update(iocs)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue
        except Exception as e:
            logger.error(f"Error reading known IOCs from digest: {e}")
            
        return known_iocs

    def extract_and_append(self, daily_report: str):
        """Extracts JSON digest from daily report and appends to the log."""
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'prompt_digest.txt')
        
        try:
            with open(template_path, 'r') as f:
                prompt_template = f.read()
        except FileNotFoundError:
            logger.error(f"Digest template not found at {template_path}")
            return

        prompt = prompt_template.replace('{{daily_report}}', daily_report)
        
        try:
            logger.info("Extracting daily digest via AI...")
            # We use a system prompt that enforces JSON
            system_prompt = "You are a JSON extractor. Output ONLY raw JSON."
            response_text = self.ai_client.generate_text(system_prompt, prompt)
            
            # Clean up response in case LLM added markdown
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            digest_data = json.loads(response_text)
            
            # Enrich with novel IOC flag
            known_iocs = self._get_known_iocs()
            current_iocs = digest_data.get('iocs', [])
            novel_iocs = [ioc for ioc in current_iocs if ioc not in known_iocs]
            digest_data['novel_iocs'] = novel_iocs
            digest_data['has_novel_iocs'] = len(novel_iocs) > 0
            
            # Ensure date is present
            if 'date' not in digest_data:
                digest_data['date'] = datetime.now().strftime('%Y-%m-%d')

            # Append to file
            logger.info(f"Appending digest to {self.digest_path}")
            with open(self.digest_path, 'a') as f:
                f.write(json.dumps(digest_data) + '\n')
            
            logger.info("Daily digest successfully appended.")
            return digest_data
            
        except Exception as e:
            logger.error(f"Failed to extract or append digest: {e}")
            return None

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    try:
        ai = NVIDIAClient()
        manager = DigestManager(ai)
        # manager.extract_and_append("Some daily report content...")
    except Exception as e:
        print(f"Digest init failed: {e}")
