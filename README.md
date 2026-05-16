<div align="center">

<!-- Animated Header Banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:00ff88,100:00bfff&height=200&section=header&text=CyberRakshak%20AI&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=AI-Powered%20Cybersecurity%20Intelligence%20Bot&descAlignY=58&descSize=18&animation=fadeIn" width="100%"/>

<!-- Animated Shield -->
<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=18&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=🛡️+Threat+Analysis+%7C+IOC+Enrichment+%7C+Phishing+Detection;🔍+VirusTotal+%7C+AbuseIPDB+%7C+URLhaus+%7C+URLScan;🧠+Google+Gemini+AI+%7C+Redis+%7C+Aiogram+3;⚡+Async+Threat+Orchestration+%7C+Python+3.11" alt="Typing SVG" />

<br/>

<!-- Badges Row 1 -->
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Aiogram](https://img.shields.io/badge/Aiogram-3.x-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://aiogram.dev)
[![Redis](https://img.shields.io/badge/Redis-Cache-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

<!-- Badges Row 2 -->
[![Gemini](https://img.shields.io/badge/Google-Gemini_AI-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-00FF88?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=statuspage&logoColor=white)]()

</div>

---

<div align="center">

## 🛡️ What is CyberRakshak AI?

</div>

**CyberRakshak AI** ("Cyber Guardian" in Hindi) is an AI-powered cybersecurity intelligence Telegram bot that protects users from digital threats in real time. It analyzes suspicious domains, Telegram usernames, phishing texts, and indicators of compromise (IOCs) using a multi-provider async threat engine and Google Gemini AI for clear, defensive explanations.

> _Rakshak (रक्षक) — Hindi for "Guardian" or "Protector."_

---

## ✨ Features

<div align="center">

| Feature | Description |
|:---:|:---|
| 🔍 **Domain Reputation Analysis** | Checks URLs and IPs against multiple live threat intelligence feeds |
| 🛡️ **Telegram Username Risk Analysis** | Detects impersonation patterns and risk signals on Telegram usernames |
| ⚡ **Async Threat Orchestration** | Concurrent multi-provider queries via `asyncio` + `aiohttp` for blazing speed |
| 📊 **Threat Scoring Engine** | Weighted `0–100` confidence scoring across Low / Medium / High / Critical levels |
| 🧠 **Gemini AI Explanations** | Structured threat reports explained safely and clearly by Google Gemini |
| 🧵 **User History Tracking** | Stores sanitized activity history — never raw passwords or sensitive data |
| ⚙️ **Redis Caching & Anti-Spam** | Indicator-hash caching, rate limiting, and copy-paste spam protection |
| 🌐 **Multi-Provider IOC Enrichment** | VirusTotal · AbuseIPDB · URLhaus · URLScan integrated as modular plugins |
| 📁 **SQLite Persistence** | Fast local storage for analytics, history, and user tracking |
| 📡 **Real-Time Telegram Bot** | Aiogram 3 powered for fast, async Telegram update handling |
| 🧪 **Modular Plugin Architecture** | Easily extend with new threat feeds and intelligence providers |

</div>

---

## 🏗️ Tech Stack

<div align="center">

```
┌─────────────────────────────────────────────────────────┐
│                    CyberRakshak AI                      │
├──────────────────────┬──────────────────────────────────┤
│  🤖 Bot Framework    │  Aiogram 3 (Python 3.11)         │
│  🧠 AI Engine        │  Google Gemini API               │
│  🔍 Threat Intel     │  VirusTotal · AbuseIPDB ·        │
│                      │  URLhaus · URLScan               │
│  ⚡ Concurrency      │  asyncio + aiohttp               │
│  🗄️ Cache/Rate Limit │  Redis                           │
│  📁 Persistence      │  SQLite + aiosqlite              │
│  🐳 Infrastructure   │  Docker + Docker Compose         │
└──────────────────────┴──────────────────────────────────┘
```

</div>

---

## 🧠 Architecture Overview

```
User Input (Telegram)
        │
        ▼
┌───────────────────┐
│  Aiogram Bot Layer│  ← Rate Limiting · Security Sanitization Middleware
└────────┬──────────┘
         │
         ▼
┌────────────────────────┐
│ PhishingDetector        │  ← URL/IP extraction + heuristics
└────────┬───────────────┘
         │ (async fan-out)
    ┌────┴─────────────────────────────────┐
    ▼         ▼           ▼               ▼
VirusTotal  AbuseIPDB  URLhaus         URLScan
    └────────────┬─────────────────────────┘
                 ▼
     ┌───────────────────────┐
     │  Risk Scoring Engine  │  ← 0–100 weighted threat score
     │  Confidence Engine    │  ← verdict reliability score
     └──────────┬────────────┘
                ▼
     ┌──────────────────────┐
     │  Gemini AI Engine    │  ← safe, user-friendly verdict explanation
     └──────────┬───────────┘
                ▼
     ┌──────────────────────┐
     │  Redis Cache Layer   │  ← hash-keyed caching · anti-spam
     │  SQLite Layer        │  ← user history · analytics
     └──────────────────────┘
                ▼
       Response → Telegram
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Narayan-Kumar-Yadav/CyberRakshakAI.git
cd CyberRakshakAI
```

### 2. Create Virtual Environment

```bash
py -3.11 -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start Redis via Docker

```bash
docker run -d -p 6379:6379 redis
```

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and fill in your keys:

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

### 6. Run the Bot

```bash
python -m app.main
```

---

## 🐳 Docker Deployment

Full production deployment with Docker Compose (includes bot + Redis + persistent volume):

```bash
docker compose up --build -d
docker compose logs -f bot
```

The `bot_data` volume persists your SQLite database across container restarts.

---

## 📌 Bot Commands

| Command | Description |
|---|---|
| `/start` | Introduction and safety notice |
| `/help` | List all available commands |
| `/analyze <target>` | Full threat intelligence report for a URL, IP, or domain |
| `/scan <text>` | Detect phishing or scam indicators in a message |
| `/username @handle` | Analyze a Telegram username for risk signals |
| `/history` | View your recent safe activity summaries |

**Example:**
```
/analyze malicious-site.ru
/scan "Congratulations! You've won $1,000,000. Click here to claim."
/username @susp1c10us_acc0unt
```

---

## 🔐 Security Notice

> ⚠️ **Never expose the following in public repositories or logs:**

- Telegram bot tokens
- API keys (VirusTotal, Gemini, AbuseIPDB, URLScan)
- `.env` files
- Session tokens
- Database dumps (`*.sqlite3`)

The bot **intentionally does not store** raw passwords, private keys, or sensitive API responses. All indicators are hashed before caching in Redis. **Always rotate keys before deploying to production.**

---

## 🛣️ Roadmap

- [ ] Advanced phishing detection ML model
- [ ] IOC graph correlation
- [ ] Campaign clustering & pattern analysis
- [ ] Threat actor attribution
- [ ] Malware URL sandboxing
- [ ] AI-powered phishing classifier
- [ ] Admin dashboard (web UI)
- [ ] Threat feed streaming (real-time)

---

## 📸 Screenshots

### Threat Analysis | Username Risk | IOC History

<img width="1536" height="1024" alt="test" src="https://github.com/user-attachments/assets/463f19f0-e42b-40e9-ab28-bbdeba5240f6" />


---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open a [GitHub Issue](https://github.com/Narayan-Kumar-Yadav/CyberRakshakAI/issues) or submit a pull request.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## ⭐ Disclaimer

This project is intended for **cybersecurity research, educational purposes, and defensive security analysis only.** Users are solely responsible for complying with the Terms of Service of all integrated third-party APIs (VirusTotal, AbuseIPDB, URLScan, Google Gemini).

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00bfff,50:00ff88,100:0d1117&height=120&section=footer" width="100%"/>

**Made with 🛡️ and ❤️ for a safer internet**

[![GitHub](https://img.shields.io/badge/GitHub-Narayan--Kumar--Yadav-181717?style=for-the-badge&logo=github)](https://github.com/Narayan-Kumar-Yadav)

</div>
