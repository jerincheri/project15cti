# 🛡️ Project15CTI

A real-time Cyber Threat Intelligence dashboard built with Flask, MongoDB, VirusTotal API, and AbuseIPDB.

## Features
- IOC lookup (IP/Domain)
- Threat level classification
- Tagging and source breakdown
- Real-time visualizations with Plotly
- Export and history tracking

## Setup
```bash
git clone https://github.com/jerincheri/project15cti.git
cd project15cti
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
