<p align="center">
  <img src="docs/banner.png" alt="ForensAI Nexus Banner" width="800">
</p>

# 🧠 ForensAI Nexus  
### *AI-Powered Digital Forensics & Cyber Threat Intelligence Platform*  

![Python](https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikitlearn)
![OpenAI](https://img.shields.io/badge/OpenAI-LLM-black?logo=openai)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-green?logo=virustotal)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/github/actions/workflow/status/vismaya2xx4/ForensAI-Nexus/ci.yml?label=tests)

---

## 🔍 Overview  

**ForensAI Nexus** is an **AI-powered digital forensics and cyber threat intelligence platform** built to assist investigators, analysts, and cybersecurity teams.  
It automates forensic evidence triage, generates LLM-based log summaries, and fetches live threat intelligence — all in one streamlined Python tool.

> 🧬 **Core mission:** Simplify forensic analysis using machine learning, GPT-powered insights, and real-time threat data.

---

## ⚙️ Features  

✅ **AI Evidence Triage** – Random Forest ML model classifies files by malware risk  
✅ **LLM Forensic Summaries** – GPT model converts raw security logs into clear English  
✅ **Threat Intelligence Integration** – VirusTotal API lookups for live malware verdicts  
✅ **Automated Reporting** – JSON and HTML report generation  
✅ **Rich Console Output** – Clean, colorized interface with emojis and tables  
✅ **Error Resilience** – Graceful handling of missing or invalid API keys  

---

## 🧰 Tech Stack  

| Component | Technology |
|------------|-------------|
| Programming | Python 3.13 |
| ML Model | scikit-learn (RandomForestClassifier) |
| LLM Integration | OpenAI GPT API |
| Threat Intelligence | VirusTotal REST API |
| Data Handling | pandas, numpy |
| Visualization | rich |
| Environment | dotenv |

---

## 🚀 Installation  

### 1️⃣ Clone the repository  
```bash
git clone https://github.com/vismaya2xx4/ForensAI-Nexus.git
cd ForensAI-Nexus
