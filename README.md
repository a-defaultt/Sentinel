# Project Sentinel: Automated SOC Pipeline with NVIDIA AI

Project Sentinel is a fully automated, Dockerized SOC pipeline designed to ingest Wazuh SIEM alerts, enrich indicators of compromise (IOCs), maintain a historical vector memory using ChromaDB, and generate AI-driven security reports via the NVIDIA Build API.

---

## 🌟 Key Features

- **Automated Ingestion:** Efficiently parses Wazuh `alerts.json`, filters high-priority events (Level 10+), and aggregates repeated alerts using Pandas.
- **Threat Intelligence Enrichment:** Automatically enriches IPs and hashes using **AbuseIPDB** and **VirusTotal** APIs with built-in rate limiting.
- **Historical Vector Memory (RAG):** Uses **ChromaDB** to store and query historical threat data. Features a 2-stage retrieval pipeline with the `nv-embedqa-e5-v5` embedding model and `rerank-qa-mistral-4b` reranker for optimal context.
- **AI-Driven Reporting:** Leverages **NVIDIA Build API** (`llama-3.3-nemotron-super-49b`) to generate professional daily and monthly security reports.
- **Multi-Channel Dispatch:** Delivers full HTML reports via **SMTP Email** and high-level executive briefings via **Webhooks**.
- **Self-Synthesizing Monthly Reports:** Maintains a daily digest log (`monthly_digest.jsonl`) that is synthesized into a strategic threat landscape report on the first of every month.
- **Dockerized Architecture:** Seamless deployment with persistent storage for vector memory and logs.

---

## 🏗️ Architecture

```text
Sentinel/
├── main.py                # Pipeline orchestration & scheduling
├── core/
│   ├── ingestion.py       # Wazuh alert parsing & normalization
│   ├── enrichment.py      # IP/Hash reputation lookups
│   ├── memory.py          # ChromaDB vector store management
│   ├── ai_client.py       # NVIDIA Build API interface
│   ├── dispatch.py        # Email & Webhook delivery
│   ├── digest.py          # Daily JSON summary extraction
│   └── monthly.py         # Monthly synthesis engine
└── templates/             # LLM Prompt templates
```

---

## 🚀 Getting Started

### Prerequisites

- Docker and Docker Compose
- NVIDIA Build API Key
- (Optional) VirusTotal and AbuseIPDB API Keys
- SMTP Server access (e.g., Gmail App Password)

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/Sentinel.git
   cd Sentinel
   ```

2. **Configure Environment Variables:**
   Copy the example environment file and fill in your details:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your API keys and configuration.

3. **Mount Wazuh Logs:**
   Ensure the volume mapping in `docker-compose.yml` points to your actual Wazuh alerts file:
   ```yaml
   volumes:
     - /var/ossec/logs/alerts/alerts.json:/app/data/alerts.json:ro
   ```

4. **Launch the Pipeline:**
   ```bash
   docker-compose up -d --build
   ```

---

## 📅 Schedule

- **Daily Report:** Runs at **08:00 AM** every day.
- **Monthly Report:** Runs at **00:00 Midnight** on the 1st of every month.

To trigger an immediate run for testing, set `RUN_NOW=true` in your `.env` file and restart the container.

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **Data:** Pandas, ChromaDB
- **AI/LLM:** NVIDIA NIM (Llama 3.3 Nemotron, Mistral)
- **APIs:** VirusTotal, AbuseIPDB
- **Containerization:** Docker

---

## 🛡️ Security & Best Practices

- **API Keys:** Never commit your `.env` file to source control.
- **Read-Only Access:** The Wazuh alerts file is mounted as read-only to ensure system integrity.
- **Data Persistence:** Vector memory and digest logs are persisted in local volumes (`./chroma_data` and `./data`).

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
