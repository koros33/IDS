# src/alert_manager.py
import json, os
os.makedirs("logs", exist_ok=True)

def write_alert(alert: dict, filename="logs/alerts.log"):
    # Ensure mitre is always present (avoid None)
    alert.setdefault("mitre", {})
    line = json.dumps(alert, ensure_ascii=False)
    with open(filename, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    # nice console output
    mid = alert['mitre'].get('technique_id') or "-"
    tname = alert['mitre'].get('technique_name') or "-"
    print(f"[ALERT] {alert.get('severity','?').upper()} {alert.get('rule_id')} {mid} {tname}")
    print("  desc:", alert.get("description"))
    print("  evidence:", alert.get("evidence")[:160].replace("\n"," "))
