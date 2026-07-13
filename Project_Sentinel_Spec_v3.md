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
- **Real-time (Immediate):** Continuous monitoring of `alerts.json` for critical (Level 12+) events, *or* any alert matching the GridPulse threat intel feed regardless of level, triggering instant webhook notifications and (on IP matches) SOAR blocking.
- **Daily (08:00 AM):** GridPulse feed sync, comprehensive forensic audit, deep RCA, and automated remediation recommendations.
- **Monthly (1st, 00:00):** Strategic synthesis of the threat landscape and MITRE Tactic Heatmaps.

### Threat Intel Feed Integration
Sentinel consumes the IOC feed published by **GridPulse** to a shared Google Sheet via a read-only service account (`spreadsheets.readonly` — Sentinel can never write to the feed). The sheet is synced to a local JSON cache once per daily run and reloaded by the real-time monitor whenever the cache changes (mtime check, no polling overhead). Alerts whose `srcip` or file hash appears in the feed are escalated to Level 15 and flagged with the matched indicator's source.

---

## 2. Directory Structure

wazuh-ai-reporter/
├── main.py                        # Entry point, scheduler, job orchestration & monitor thread
├── config.py                      # .env loading, all environment variables
├── core/
│   ├── ingestion.py               # Log reading, forensic field extraction, aggregation
│   ├── monitor.py                 # Real-time non-blocking file watcher (rotation/truncation aware)
│   ├── response.py                # Wazuh API client for SOAR actions (guardrailed)
│   ├── enrichment.py              # VirusTotal + AbuseIPDB API handlers + GridPulse IOC matching
│   ├── google_sheets_client.py    # Read-only sync of the shared GridPulse IOC feed
│   ├── memory.py                  # ChromaDB init, embed, store, query, rerank
│   ├── ai_client.py               # NVIDIA API: Nemotron, Mistral fallback, reranker
│   ├── dispatch.py                # SMTP email (sanitized) + webhook POST logic, retried
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

- Runs in a background `threading.Thread(daemon=True)`, restarted automatically if the loop ever raises.
- Uses `core.monitor.AlertMonitor.tail_alerts()`, which detects file rotation (inode change) and truncation and reopens transparently — a single-file bind mount survives Wazuh's log rotation.
- Every alert is checked against the GridPulse IOC cache (reloaded when its mtime changes); alerts trigger a webhook if `rule.level >= 12` **or** the alert matches a GridPulse indicator, whichever comes first.
- On an IP-type GridPulse match, the source IP is additionally routed to `core.response.WazuhResponseManager` for SOAR blocking (subject to the guardrails below).
- Triggers `Dispatcher.send_webhook` immediately upon detection.

---

## 8. SOAR Action Execution

- **Modes:** `AUDIT` (log actions only) or `ENFORCE` (execute via the Wazuh Active Response API).
- **Supported Actions:** `BLOCK_IP` (`!firewall-drop` — the `!` prefix runs the script directly from `active-response/bin/`, requiring no `<active-response>` block on the manager), `ISOLATE_HOST` (gated behind `SOAR_ALLOW_ISOLATE=true`; currently reports failure honestly as it is not yet implemented).
- **Triggers:** `main.py` parses the `AUTOMATED ACTIONS JSON` block from the AI report (confidence >= 8), and the real-time monitor triggers `BLOCK_IP` directly on GridPulse IP matches.
- **Guardrails (apply in both modes):** private/loopback/reserved/invalid targets and any IP in `SOAR_PROTECTED_IPS` are refused; executed actions are capped at `SOAR_MAX_ACTIONS_PER_HOUR` (default 5); the Wazuh API's token is refreshed automatically on expiry.
- **Honest reporting:** the Wazuh API returns HTTP 200 even when a command reaches zero agents (e.g. an invalid or disconnected agent ID) — `execute_action` checks `total_affected_items` and only reports success when the command actually dispatched.
