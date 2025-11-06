# ForensAI Nexus
**Tagline:** *AI-Powered Digital Forensics & Cyber Threat Intelligence Platform*

ForensAI Nexus demonstrates an end-to-end, portfolio-ready pipeline:
- 🤖 **AI Evidence Triage:** Random Forest ranks files by malware risk
- 🧠 **LLM Forensic Summaries:** OpenAI GPT turns raw logs into plain-English insight
- 🔬 **Threat Intelligence:** VirusTotal API lookup for known-malware hashes
- 📝 **Automated Reporting:** Consolidated JSON report for your investigation

---

## ✨ Features
- Scikit-learn RandomForestClassifier trained on a realistic dataset
- OpenAI Chat Completions (with offline fallback if no API key)
- VirusTotal v3 hash lookup (with graceful error handling)
- Rich console output with tables & emojis
- Tests to verify the critical paths

---

## 🧱 Tech Stack
- Python 3.8+
- pandas, numpy, scikit-learn
- OpenAI (LLM)
- VirusTotal (CTI)
- requests, python-dotenv, rich

---

## 🚀 Quickstart

```bash
git clone <your-fork-or-repo-url>
cd ForensAI-Nexus

# 1) Create venv & install
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt

# 2) Configure environment
cp .env .env.backup  # if you want a backup
# Edit .env and set:
# OPENAI_API_KEY=your_key
# OPENAI_MODEL=gpt-4o-mini
# VT_API_KEY=your_virustotal_key

# 3) Run the demo
python main.py

# 4) Run tests
pytest -q
