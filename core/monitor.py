"""
Monitor Module for Project Sentinel.
Real-time tailing of Wazuh alerts.json with critical event filtering.
"""
import time
import json
import os
import logging
from typing import Generator, Dict, Any
from config import ALERTS_JSON_PATH, logger

class AlertMonitor:
    def __init__(self, file_path: str = str(ALERTS_JSON_PATH)):
        self.file_path = file_path

    def tail_alerts(self) -> Generator[Dict[str, Any], None, None]:
        """
        Tails the alerts file and yields new lines as JSON objects.
        
        This method implementation is non-blocking and efficient, 
        suitable for background monitoring.
        """
        if not os.path.exists(self.file_path):
            logger.error(f"Alerts file not found: {self.file_path}")
            return

        with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
            # Move pointer to the end of file to ignore existing historical alerts
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    # No new alerts, wait briefly before checking again
                    time.sleep(0.1) 
                    continue
                
                try:
                    alert = json.loads(line)
                    yield alert
                except json.JSONDecodeError:
                    # Skip malformed lines
                    continue

    def monitor_critical(self, min_level: int = 12) -> Generator[Dict[str, Any], None, None]:
        """
        Yields only critical alerts based on the specified level.
        
        Args:
            min_level (int): The threshold for critical alerts (default: 12).
        """
        logger.info(f"Starting real-time monitoring for level >= {min_level} alerts.")
        for alert in self.tail_alerts():
            try:
                level = alert.get('rule', {}).get('level', 0)
                if level >= min_level:
                    logger.info(f"CRITICAL ALERT DETECTED: Level {level} - {alert.get('rule', {}).get('description')}")
                    yield alert
            except Exception as e:
                logger.error(f"Error filtering alert: {e}")

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    monitor = AlertMonitor()
    # for alert in monitor.monitor_critical(1):
    #     print(alert)
