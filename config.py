import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Setup logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("SentinelConfig")

# Base Directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
CHROMA_DATA_PATH = Path(os.getenv("CHROMA_DATA_PATH", "/app/chroma_data"))

# API Keys
NVIDIA_PRIMARY_KEY = os.getenv("NVIDIA_PRIMARY_KEY")
NVIDIA_FALLBACK_KEY = os.getenv("NVIDIA_FALLBACK_KEY")
NVIDIA_EMBEDDING_KEY = os.getenv("NVIDIA_EMBEDDING_KEY")
NVIDIA_RERANKING_KEY = os.getenv("NVIDIA_RERANKING_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Check for mandatory API keys
if not all([NVIDIA_PRIMARY_KEY, NVIDIA_FALLBACK_KEY, NVIDIA_EMBEDDING_KEY, NVIDIA_RERANKING_KEY]):
    logger.error("One or more NVIDIA API Keys are missing (Primary, Fallback, Embedding, or Reranking).")
if not VIRUSTOTAL_API_KEY:
    logger.warning("VIRUSTOTAL_API_KEY is missing; IOC enrichment will be limited.")
if not ABUSEIPDB_API_KEY:
    logger.warning("ABUSEIPDB_API_KEY is missing; IOC enrichment will be limited.")

# NVIDIA Build API Models
PRIMARY_MODEL = "nvidia/llama-3.3-nemotron-super-49b-v1"
FALLBACK_MODEL = "mistralai/mistral-small-2409" # Adjusted to a likely valid ID
EMBEDDING_MODEL = "nvidia/nv-embedqa-e5-v5"
RERANKER_MODEL = "nvidia/nv-rerankqa-mistral-4b-v3"

# NVIDIA Settings
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_TIMEOUT = int(os.getenv("NVIDIA_TIMEOUT_SECONDS", 45))
NVIDIA_FALLBACK_TIMEOUT = 30

# File Paths
ALERTS_JSON_PATH = Path(os.getenv("ALERTS_JSON_PATH", "/app/data/alerts.json"))
MONTHLY_DIGEST_PATH = DATA_DIR / "monthly_digest.jsonl"

# Pipeline Settings
MIN_RULE_LEVEL = int(os.getenv("MIN_RULE_LEVEL", 10))
DAILY_REPORT_TIME = "08:00"
MONTHLY_REPORT_TIME = "00:00"

# SMTP Settings
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM")
SMTP_TO = os.getenv("SMTP_TO")

# Webhook Settings
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

# Rate Limiting
VT_REQ_PER_MIN = 4
ABUSEIPDB_DAILY_LIMIT = 1000

# Validation of critical paths
for path in [DATA_DIR, CHROMA_DATA_PATH]:
    if not path.exists():
        try:
            path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {path}")
        except Exception as e:
            logger.error(f"Failed to create directory {path}: {e}")

logger.info("Configuration loaded successfully.")
