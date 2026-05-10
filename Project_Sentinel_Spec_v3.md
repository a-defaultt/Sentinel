# Project Sentinel — Wazuh AI Daily & Monthly Reporter
### Full Technical Specification · v3.0

---

## Quick Reference

| Attribute | Value | Attribute | Value |
|-----------|-------|-----------|-------|
| Purpose | Automated SOC pipeline | Language | Python 3.11+ |
| Deployment | Dockerized scheduler | AI Provider | NVIDIA Build API |
| Reports | Daily + Monthly | Vector DB | ChromaDB (local persistent) |
| Enrichment | VirusTotal + AbuseIPDB | Scheduling | schedule library |

---

## 1. Project Overview

Project Sentinel is a fully automated, Dockerized SOC pipeline that runs on a scheduled basis to ingest Wazuh SIEM alerts, filter and aggregate critical events, enrich indicators of compromise (IOCs) via external threat intelligence APIs, maintain a persistent vector memory of historical threats, and generate AI-driven security reports using large language models hosted on the NVIDIA Build API.

The system produces two report cadences:

- **Daily report (08:00 AM):** filters the previous day's alerts, enriches IOCs, queries historical memory, and generates a full security report plus a 3-bullet executive briefing. Dispatched via SMTP email and webhook POST.
- **Monthly report (00:00 Midnight, 1st of the month):** synthesizes 30 daily digest entries plus a cross-month ChromaDB query into a comprehensive threat landscape narrative. 

A key design principle is the **daily digest file** (`monthly_digest.jsonl`). After each daily report is generated, a second lightweight AI extraction pass produces a structured JSON summary of that day's most important events and appends it to this file. The monthly report reads all 30 entries plus pre-computed Python aggregates (Option B), so the LLM reasons over clean structured data.

---

## 2. Directory Structure

wazuh-ai-reporter/
├── main.py                        # Entry point, scheduler, job orchestration
├── config.py                      # .env loading, all environment variables
├── core/
│   ├── ingestion.py               # Log reading, filtering (level>=10), aggregation
│   ├── enrichment.py              # VirusTotal + AbuseIPDB API handlers
│   ├── memory.py                  # ChromaDB init, embed, store, query, rerank
│   ├── ai_client.py               # NVIDIA API: Nemotron, Mistral fallback, reranker
│   ├── dispatch.py                # SMTP email + webhook POST logic
│   ├── digest.py                  # Daily digest extractor (second AI pass)
│   └── monthly.py                 # Monthly report orchestrator
├── templates/
│   ├── prompt_system.txt          # Base system prompt for daily report
│   ├── prompt_digest.txt          # Extraction prompt for digest.py
│   └── prompt_monthly.txt         # System prompt for monthly report
├── data/
│   ├── monthly_digest.jsonl               # Live current-month digest (one entry/day)
│   └── monthly_digest_YYYY-MM.jsonl       # Archived after each month-end run
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example


---

## 3. Technical Stack & Dependencies

| Component | Library / Tool | Purpose |
|-----------|---------------|---------|
| Language | Python 3.11+ | Runtime |
| Data processing | pandas | Alert parsing, aggregation, groupby |
| Vector database | chromadb (local persistent) | Historical alert embedding & search |
| AI provider | NVIDIA Build API | LLM generation, embedding, reranking |
| Threat intel | VirusTotal API v3 | Hash reputation lookup |
| Threat intel | AbuseIPDB API v2 | IP reputation + confidence score |
| Scheduling | schedule (Python) | Daily 08:00 + monthly 00:00 |
| Email | smtplib (stdlib) | SMTP dispatch with attachments |
| Containerization | Docker + Compose | Isolated runtime, volume mapping |

---

## 4. AI Model Hierarchy

All AI calls go to the NVIDIA Build API (`api.nvidia.com`). The same `NVIDIA_API_KEY` authenticates all four model endpoints.

| Role | Model ID | Context | Used for |
|------|----------|---------|----------|
| Primary writer | `llama-3.3-nemotron-super-49b` | 128k | Daily report, monthly report, digest extraction |
| Fallback writer | `mistral-small-4-118b` | 32k | Triggered by 5xx or timeout from Nemotron (try/except) |
| Embedder | `nv-embedqa-e5-v5` | 512 tok | Embedding alert chunks for ChromaDB storage and query |
| Reranker | `rerank-qa-mistral-4b` | N/A | Scoring top-20 ChromaDB results down to top 5 |

**Fallback trigger:** any exception from the Nemotron call.
**Timeout threshold:** set `NVIDIA_TIMEOUT_SECONDS` in `.env` (recommended: 45s for Nemotron, 30s for Mistral).

---

## 5. Daily Pipeline (08:00 AM)

Triggered by the `schedule` library at 08:00 every day. 

### Phase 1 — Ingestion & Normalization
- **Input:** `/app/data/alerts.json` (mounted read-only)
- **Filter:** Drop any event where `rule.level < 10`.
- **Extract fields:** `timestamp`, `rule.level`, `rule.id`, `rule.description`, `mitre.id`, `agent.name`, `srcip`, `dstuser`, `hashes`, `service_abused`, `port`, `cve`, `ssh_key_fingerprint`
- **Aggregate:** Group by composite key (`rule.id` + `srcip`). Collapse repeated events into a single record with a `count` field.

### Phase 2 — IOC Enrichment
- Send unique IPs to **AbuseIPDB API v2**. Extract: `abuseConfidenceScore`, `countryCode`, `isp`, `usageType`.
- Send unique hashes to **VirusTotal API v3**. Extract: malicious vendor count, harmless count.
- **Rate limiting:** Respect AbuseIPDB (1000/day) and VirusTotal (4 req/min) limits using `time.sleep()`.

### Phase 3 — Historical Memory (RAG)
- **Chunking strategy:** Truncate fields if >512 tokens (drop port, dstuser, etc. before rule ID/IP).
- **Metadata Flattening:** ChromaDB metadata does not support lists. Flatten lists (e.g., `mitre_ids`) into comma-separated strings (e.g., `"T1110.001, T1190"`).
- Embed chunks via `nv-embedqa-e5-v5` and store in ChromaDB.
- Query ChromaDB for top 20 nearest vectors using today's IOCs. Pass to `rerank-qa-mistral-4b`, extract top 5, and inject into LLM payload.

### Phase 4 — AI Report Generation
- **Payload:** System prompt + today's JSON + top 5 historical contexts.
- **Required Sections:** Narrative, Watchlist, Wazuh rules (XML blocks), Briefing (exactly 3 bullets delimited by markers like ``).

### Phase 5 — Digest Extraction (digest.py)
- Runs second AI call (`prompt_digest.txt`) for JSON extraction only.
- Compares against `known_iocs` from the last 7 days of `monthly_digest.jsonl` to flag novel IOCs.
- Appends validated schema as a JSON line to `data/monthly_digest.jsonl`.

### Phase 6 — Dispatch (dispatch.py)
- Split Briefing from full report body. Send Full Report via SMTP HTML email (with JSON/CSV attachments).
- Send Briefing via Webhook POST.

---

## 6. Monthly Pipeline (00:00 Midnight, 1st of month)

Triggered by `schedule` at 00:00. Scheduling this at midnight while the daily runs at 08:00 prevents blocking overlap from API rate limits.

### Step 1 — Read & aggregate digest
- Read 28–31 entries from `data/monthly_digest.jsonl`.
- Compute Python-side aggregates (Option B): `mitre_heatmap`, `top_ips`, `busiest_days`, `novel_ioc_list`, `recommendation_pool`.

### Step 2 — Cross-month ChromaDB query
- Query ChromaDB (excluding current month) using top 3 MITRE tactics. Rerank to top 5.

### Step 3 — Monthly AI call
- **Payload:** System prompt, Python aggregates, 30 digests, 5 cross-month contexts.
- **Required Sections:** Threat landscape narrative, Top IOC watchlist, MITRE tactic heatmap, Hardening recommendations, Executive briefing (exactly 5 bullets).

### Step 4 — Monthly dispatch & archive
- Dispatch via Email and Webhook. Archive `monthly_digest.jsonl` to `monthly_digest_YYYY-MM.jsonl`.

---

## 7. Scheduler (main.py)

```python
import schedule, time
from datetime import date

# Note: Add logic to check if today is the 1st of the month for the 00:00 job
schedule.every().day.at("08:00").do(run_daily_pipeline)
schedule.every().day.at("00:00").do(run_monthly_pipeline_if_first_day)

while True:
    schedule.run_pending()
    time.sleep(30)

---

## 8. Docker Configuration
docker-compose.yml

services:
  sentinel:
    build: .
    env_file: .env
    restart: unless-stopped
    volumes:
      - /var/ossec/logs/alerts/alerts.json:/app/data/alerts.json:ro
      - ./chroma_data:/app/chroma_data
      - ./data:/app/data

---

## 9. requirements.txt

pandas>=2.0
chromadb>=0.5
openai>=1.0
requests>=2.31
schedule>=1.2
python-dotenv>=1.0
tiktoken>=0.7
markdown>=3.5