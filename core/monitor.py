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

        Survives the conditions a long-lived tail hits in production:
        - file missing at startup or later (retries instead of returning)
        - rotation (rename + recreate: inode change is detected, the new
          file is read from the beginning so no alerts are lost)
        - truncation in place (file size shrinks below our offset)
        - partial writes (incomplete lines are re-read once complete)
        """
        f = None
        inode = None
        skip_to_end = True  # only skip history on the very first open
        while True:
            if f is None:
                try:
                    f = open(self.file_path, 'r', encoding='utf-8', errors='replace')
                    inode = os.fstat(f.fileno()).st_ino
                    if skip_to_end:
                        f.seek(0, os.SEEK_END)
                        skip_to_end = False
                    logger.info(f"Tailing alerts file: {self.file_path} (inode {inode})")
                except OSError:
                    logger.warning(f"Alerts file not available: {self.file_path}. Retrying in 5s.")
                    time.sleep(5)
                    continue

            pos = f.tell()
            line = f.readline()
            if line:
                if not line.endswith('\n'):
                    # Partial write — rewind and wait for the rest of the line
                    f.seek(pos)
                    time.sleep(0.1)
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
                continue

            # No new data: check for rotation or truncation before waiting
            try:
                st = os.stat(self.file_path)
                if st.st_ino != inode or st.st_size < f.tell():
                    logger.info("Alerts file rotated or truncated. Reopening.")
                    f.close()
                    f = None
                    continue
            except OSError:
                # File disappeared mid-rotation; reopen when it returns
                f.close()
                f = None
                continue
            time.sleep(0.5)

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
