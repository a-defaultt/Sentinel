import os
import time
import glob
import logging
from main import ProjectSentinel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MonthProcessor")

def process_logs(log_dir):
    # Set to AUDIT mode to prevent accidental blocking based on historical data
    os.environ["SOAR_MODE"] = "AUDIT"

    # Get all JSON compressed files
    log_files = sorted(glob.glob(os.path.join(log_dir, "ossec-alerts-*.json.gz")))

    if not log_files:
        logger.error(f"No log files found in {log_dir}")
        return

    logger.info(f"Found {len(log_files)} log files to process.")

    # One instance for the whole batch — config is frozen at import time,
    # so the file path must be passed per run, not via environment variables
    # (setting ALERTS_JSON_PATH here had no effect and every iteration used
    # to silently reprocess the same default file)
    sentinel = ProjectSentinel()

    for log_file in log_files:
        logger.info(f"--- Processing: {log_file} ---")

        try:
            sentinel.run_daily_pipeline(alerts_path=log_file)
        except Exception as e:
            logger.error(f"Failed to process {log_file}: {e}")

        # Brief pause to respect API rate limits
        logger.info("Waiting 10 seconds before next file...")
        time.sleep(10)

if __name__ == "__main__":
    LOGS_DIR = os.getenv("HISTORICAL_LOGS_DIR", "./historical_logs")
    process_logs(LOGS_DIR)
