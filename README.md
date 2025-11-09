# Intrusion Detection System (IDS)

## 🧠 Overview
This project is a **lightweight Intrusion Detection System (IDS)** prototype designed to detect suspicious network activity in real time.  
Built as a minimal viable product (MVP), it demonstrates how configurable rules, packet capture, and alert logging can come together to form the foundation of a defensive monitoring tool  a key skill for any **Cyber Analyst**.


## 📁 Project Structure
```

IDS_NEW/
├── config/               # YAML rule files
│   └── rules.yaml
├── data/                 # Optional: reports or stats
├── logs/                 # Alerts logged here (ids_alerts.log)
├── src/
│   ├── main.py           # CLI entry point + sniffing loop
│   ├── rule_engine.py    # Core detection logic (match → alert)
│   └── utils.py          # Logging & formatting helpers
├── tools/
│   ├── pcap_generator.py # Build attack PCAPs (SQLi, XSS, etc.)
│   └── replay_pcap.py    # Replay PCAPs to live interface
├── requirements.txt
└── README.md

````


## ⚙️ How It Works
1. **Packet Capture:**  
   The system listens to network traffic using libraries like `scapy` or `pyshark`.

2. **Rule Matching:**  
   Each packet is analyzed against signatures defined in `config/rules.yaml`.  
   When a rule matches, an alert is triggered.

3. **Alert Logging:**  
   Alerts are written to `logs/ids_alerts.log` with timestamps and rule identifiers for analysis.


## 🧩 Example Rule (`rules.yaml`)
```yaml
rules:
  - id: 001
    name: "SQL Injection Attempt"
    pattern: "SELECT.*FROM.*"
    action: "alert"
  - id: 002
    name: "XSS Attack"
    pattern: "<script>"
    action: "alert"
````



## 📊 Sample Alert (ids_alerts.log)

```
[2025-11-09 14:23:11] ALERT: Rule 001 matched → SQL Injection Attempt detected from 192.168.0.10
```


## 🧪 Testing Tools

You can simulate attacks and replay network data using the scripts under `tools/`:

* `pcap_generator.py` — creates sample PCAPs containing mock SQLi or XSS traffic.
* `replay_pcap.py` — replays generated PCAPs on a live interface for IDS testing.

---

## 🚀 How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Start IDS
python src/main.py --iface eth0 --rules config/rules.yaml
```

Logs will appear in `logs/ids_alerts.log`.


## 💡 Future Improvements

* Add rule priority and severity levels
* Integrate email or Slack alert notifications
* Build a small dashboard for visualizing alerts
* Expand rule coverage (DoS, brute-force, etc.)


