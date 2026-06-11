"""
Status Utility for Project Sentinel.
Provides a quick health check of the Docker container and the last pipeline run timestamp.
"""
import os
import sys
import json
from pathlib import Path

# Add project root to sys.path so we can import 'config'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MONTHLY_DIGEST_PATH

def check_status():
    # 1. Environment Detection
    in_container = os.path.exists('/.dockerenv')
    
    # 2. Check Docker/Container status
    if in_container:
        # If the script is running, the container is clearly online
        status = "ONLINE (Inside Container)"
    else:
        # External check (current behavior)
        status_raw = os.popen("docker ps -f name=project-sentinel --format '{{.Status}}'").read().strip()
        status = status_raw if status_raw else "OFFLINE (Run: docker-compose up -d)"
    
    # 3. Check last run success date from monthly_digest.jsonl
    last_run = "Never (or check logs)"
    if MONTHLY_DIGEST_PATH.exists():
        try:
            with open(MONTHLY_DIGEST_PATH, 'rb') as f:
                # Seek to end and read last line
                f.seek(0, os.SEEK_END)
                if f.tell() > 0:
                    f.seek(-1, os.SEEK_END)
                    # Simple backward search for newline
                    while f.read(1) != b'\n':
                        f.seek(-2, os.SEEK_CUR)
                        if f.tell() == 0: break
                    last_line = f.readline().decode('utf-8').strip()
                    if last_line:
                        entry = json.loads(last_line)
                        last_run = entry.get('date', 'Unknown')
        except Exception as e:
            last_run = f"Error reading logs: {e}"

    print(f"\n--- Project Sentinel Status ---")
    print(f"Container: {status if status else 'OFFLINE (Run: docker-compose up -d)'}")
    print(f"Last Pipeline Success: {last_run}")
    print(f"-------------------------------\n")

if __name__ == "__main__":
    check_status()
