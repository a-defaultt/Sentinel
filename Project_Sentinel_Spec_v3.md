# Project Sentinel — Wazuh AI Advanced SOC Engine
### Full Technical Specification · v4.0

---

## Quick Reference

| Attribute | Value | Attribute | Value |
|-----------|-------|-----------|-------|
| Purpose | Automated SOAR pipeline | Language | Python 3.11+ |
| Deployment | Dockerized scheduler | AI Provider | NVIDIA Build API |
| Reports | Daily + Monthly + Real-time | Vector DB | ChromaDB (local persistent) |
| Enrichment | VirusTotal + AbuseIPDB | Remediation | Wazuh Active Response API |

---

## 1. Project Overview

Project Sentinel is an advanced SOC engine that transcends traditional reporting. It combines automated ingestion, deep forensic enrichment, and real-time monitoring with AI-driven SOAR (Security Orchestration, Automation, and Response) capabilities.

### Enterprise Deployment & Air-Gap Readiness
While the current implementation utilizes the hosted NVIDIA Build API for rapid development and testing, the architecture is strictly modular. The pipeline is designed to support a **drop-in transition to on-premises NVIDIA NIM** (Neural Inference Modules) containers. This enables:
- **Fully Air-Gapped Operation:** Processing critical SOC telemetry without external API dependencies.
- **Enterprise Data Sovereignty:** Ensuring all log data remains within the corporate boundary.
- **Low Latency:** High-speed inference for real-time response actions.

The system operates on three temporal tracks:
- **Real-time (Immediate):** Continuous monitoring of `alerts.json` for critical (Level 12+) events, triggering instant webhook notifications.
- **Daily (08:00 AM):** Comprehensive forensic audit, deep RCA, and automated remediation recommendations.
- **Monthly (1st, 00:00):** Strategic synthesis of the threat landscape and MITRE Tactic Heatmaps.

---

## 2. Directory Structure

wazuh-ai-reporter/
├── main.py                        # Entry point, scheduler, job orchestration & monitor thread
├── config.py                      # .env loading, all environment variables
├── core/
│   ├── ingestion.py               # Log reading, forensic field extraction, aggregation
│   ├── monitor.py                 # Real-time non-blocking file watcher
│   ├── response.py                # Wazuh API client for SOAR actions
│   ├── enrichment.py              # VirusTotal + AbuseIPDB API handlers
│   ├── memory.py                  # ChromaDB init, embed, store, query, rerank
│   ├── ai_client.py               # NVIDIA API: Nemotron, Mistral fallback, reranker
│   ├── dispatch.py                # SMTP email + webhook POST logic
│   ├── digest.py                  # Daily JSON summary extraction
│   └── monthly.py                 # Monthly synthesis engine
├── templates/
│   ├── prompt_system.txt          # System prompt with RCA & Remediation logic
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
| Remediation | Wazuh API | Active Response execution |
| Real-time | threading + file tailing | Non-blocking hot-path monitoring |

---

## 4. AI Model Hierarchy

All AI calls go to the NVIDIA Build API (`api.nvidia.com`). The same `NVIDIA_API_KEY` authenticates all four model endpoints.

| Role | Model ID | Context | Used for |
|------|----------|---------|----------|
| Primary writer | `llama-3.3-nemotron-super-49b` | 128k | Daily report, monthly report, digest extraction |
| Fallback writer | `mistral-small-4-118b` | 32k | Triggered by 5xx or timeout from Nemotron (try/except) |
| Embedder | `nv-embedqa-e5-v5` | 512 tok | Embedding alert chunks for ChromaDB storage and query |
| Reranker | `rerank-qa-mistral-4b` | N/A | Scoring top-20 ChromaDB results down to top 5 |

---

## 5. Daily Pipeline (08:00 AM)

### Phase 1 — Ingestion & Forensic Normalization
- **Extract fields:** `timestamp`, `level`, `rule_id`, `description`, `mitre_ids`, `agent_name`, `srcip`, `dstuser`, `hashes`, `full_log`, `parent_id`, `process_name`, `command`.

### Phase 4 — AI Forensic Analysis (Deep RCA)
- **Attack Chaining:** The AI groups alerts into logical behaviors and reconstructs the step-by-step sequence of events.
- **Root Cause Analysis:** Hypothesizes the initial entry point (Initial Access vector).
- **SOAR Recommendations:** Outputs machine-readable `<action type="..." target="..." agent="..." reasoning="..." />` tags for confidence >= 8.

---

## 7. Real-Time Monitor (Hot-Path)

- Runs in a background `threading.Thread(daemon=True)`.
- Uses `core.monitor.AlertMonitor` to tail `alerts.json`.
- Filters for `rule.level >= 12`.
- Triggers `Dispatcher.send_webhook` immediately upon detection.

---

## 8. SOAR Action Execution

- **Modes:** `AUDIT` (Log actions only) or `ENFORCE` (Execute via API).
- **Supported Actions:** `BLOCK_IP` (firewall-drop), `ISOLATE_HOST`.
- **Logic:** `main.py` regex-parses `<action>` tags from the AI report and calls `core.response.WazuhResponseManager`.
