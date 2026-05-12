"""
Status Utility for Project Sentinel.
Provides a quick health check of the Docker container and the last pipeline run timestamp.
"""
import os
import json
from pathlib import Path
from config import MONTHLY_DIGEST_PATH

def check_status():
    # 1. Check Docker status
    # Note: Assumes running from outside or inside the host where docker command is available
    status = os.popen("docker ps -f name=project-sentinel --format '{{.Status}}'").read().strip()
    
    # 2. Check last run success date from monthly_digest.jsonl
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
