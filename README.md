# 🛡️ CyberRakshak AI

AI-Powered Cybersecurity Intelligence Telegram Bot built using Python, Aiogram, Redis, and asynchronous threat orchestration.

CyberRakshak AI analyzes suspicious domains, Telegram usernames, text messages, and indicators of compromise (IOCs) using multiple cybersecurity intelligence providers and AI-assisted threat analysis.

---

## 🚀 Features

* 🔍 **Domain reputation analysis:** Checks URLs against multiple intelligence feeds.
* 🛡️ **Telegram username risk analysis:** Analyzes Telegram usernames for impersonation and risk signals.
* ⚡ **Async threat orchestration:** Fast, concurrent API queries using `aiohttp` and `asyncio`.
* 📊 **Threat scoring & confidence engine:** Advanced weighting and scoring of multi-source intelligence.
* 🧠 **AI-powered security explanations:** Google Gemini safely explains verdicts in user-friendly language.
* 🧵 **User history tracking:** Stores safe user activity history without passwords or sensitive breach details.
* ⚙️ **Redis caching & async workers:** Robust caching, rate-limiting, and anti-spam controls.
* 🌐 **Multi-provider IOC enrichment:** Integrates with VirusTotal, AbuseIPDB, URLhaus, URLScan, and more.
* 📁 **SQLite persistence layer:** Fast local data storage for analytics and user tracking.
* 📡 **Real-time Telegram bot interaction:** Fast updates powered by Aiogram 3.
* 🧪 **Modular provider architecture:** Extensible plugin system to add more feeds easily.

---

## 🏗️ Tech Stack

* **Language:** Python 3.11
* **Bot Framework:** Aiogram 3
* **Caching & Rate Limiting:** Redis
* **Database:** SQLite & `aiosqlite`
* **Concurrency:** `asyncio` & `aiohttp`
* **Infrastructure:** Docker & Docker Compose
* **AI Engine:** Google Gemini API
* **Threat Intelligence:** VirusTotal, AbuseIPDB, URLhaus, URLScan APIs

---

## 📸 Screenshots

### Threat Analysis | Telegram Username Analysis | IOC History
* <img width="1536" height="1024" alt="test" src="https://github.com/user-attachments/assets/ba614db7-7bac-485b-a61d-717753795e84" />*

---

## ⚙️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/Narayan-Kumar-Yadav/CyberRakshakAI.git
cd CyberRakshakAI
```

### 2. Create Virtual Environment

```bash
py -3.11 -m venv venv
```

Activate the virtual environment:
* Windows: `.\venv\Scripts\activate`
* Linux/Mac: `source venv/bin/activate`

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start Redis Using Docker

```bash
docker run -d -p 6379:6379 redis
```

### 5. Configure Environment Variables

Create `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` and add your keys:
```env
BOT_TOKEN=your_telegram_bot_token_here

GEMINI_API_KEY=your_gemini_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here

REDIS_URL=redis://localhost:6379/0

ENABLED_PROVIDERS=virustotal,urlscan,abuseipdb,urlhaus
ADMIN_IDS=123456789
```

### 6. Run The Bot

```bash
python -m app.main
```

---

## 🐳 Docker Setup

For a full production deployment using Docker Compose:

```bash
docker compose up --build -d
docker compose logs -f bot
```

The compose stack starts both the `bot` and `redis`. SQLite data is stored in the `bot_data` volume.

---

## 📌 Example Commands

* `/start` - Introduction and safety notice.
* `/help` - Available commands.
* `/analyze google.com` - Unified threat-intelligence report for a URL, IP, or domain.
* `/scan <text>` - Detect phishing or scam indicators in text.
* `/username @name` - Analyze Telegram username risk signals.
* `/history` - View recent safe activity summaries.

---

## 🧠 Architecture Overview

CyberRakshak AI uses an asynchronous modular architecture:

* **Telegram Bot Layer:** Processes updates using `Aiogram` and customized middlewares (Rate limiting, Security sanitation).
* **Async Threat Orchestration Engine:** Concurrently dispatches indicator queries.
* **Provider Aggregation System:** Normalizes API results from VirusTotal, URLhaus, AbuseIPDB, etc.
* **Risk & Confidence Engines:** Computes weighted `0-100` scores to determine Threat Levels (Low, Medium, High, Critical).
* **AI Explanation Engine:** Passes structured JSON threat reports to Gemini to generate defensive user guidance.
* **Redis Cache Layer:** Caches API responses (by indicator hash), handles rate limits, and prevents copy-paste spam.
* **SQLite Persistence Layer:** Stores user history and sanitized analytics.

### Threat Intelligence Flow
1. User sends `/analyze <target>`.
2. `PhishingDetector` extracts URLs/IPs and heuristics.
3. Enabled providers are queried asynchronously.
4. `RiskScoringEngine` computes severity; `ConfidenceScoringEngine` computes verdict reliability.
5. `GeminiCybersecurityAssistant` explains the verdict safely.

---

## 🔐 Security Notice

**Never expose:**
* Telegram bot tokens
* API keys
* `.env` files
* Session tokens
* Database dumps (`*.sqlite3`)

The bot intentionally does not store raw passwords, private keys, or sensitive API responses in the SQLite history. All breach queries and threat indicators are hashed in Redis. **Always rotate keys before production deployment.**

---

## 🛣️ Future Roadmap

* Advanced phishing detection
* IOC graph correlation
* Campaign clustering
* Threat actor attribution
* Malware URL sandboxing
* AI-powered phishing classification
* Admin dashboard
* Threat feed streaming

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for more details.

---

## ⭐ Disclaimer

This project is intended for cybersecurity research, educational purposes, and defensive security analysis only. Users are responsible for complying with the Terms of Service of all integrated third-party APIs.
