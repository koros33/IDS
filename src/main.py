# src/main.py
import sys, json, subprocess
from rule_engine import RuleEngine
from alert_manager import write_alert

def run(pcap_path):
    engine = RuleEngine("config/rules.yaml")
    p = subprocess.Popen(["python", "tools/replay_pcap.py", pcap_path], stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        try:
            rec = json.loads(line.strip())
        except Exception:
            continue
        alerts = engine.process(rec)
        for a in alerts:
            write_alert(a)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/main.py data/sample_attack.pcap")
        sys.exit(1)
    run(sys.argv[1])
