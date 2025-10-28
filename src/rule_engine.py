# src/rule_engine.py
import yaml, re, time
from typing import List, Dict

class RuleEngine:
    def __init__(self, rule_file="config/rules.yaml"):
        with open(rule_file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        self.rules = cfg.get("rules", [])

    def _normalize_mitre(self, rule: dict) -> dict:
        """
        Ensure rule has a mitre dict with known keys.
        Accepts both:
          mitre: "T1110"
        or
          mitre:
            technique_id: "T1110"
            technique_name: "Brute Force"
            tactic: "Credential Access"
        """
        m = rule.get("mitre")
        if m is None:
            return {}
        if isinstance(m, str):
            return {"technique_id": m}
        if isinstance(m, dict):
            # keep only expected keys
            return {
                "technique_id": m.get("technique_id") or m.get("technique"),
                "technique_name": m.get("technique_name") or m.get("name"),
                "tactic": m.get("tactic")
            }
        return {}

    def process(self, packet_record: dict) -> List[Dict]:
        """
        packet_record example:
          { "src": "1.2.3.4", "dst": "5.6.7.8", "protocol": "HTTP", "payload": "..." }
        Returns list of alert dicts.
        """
        alerts = []
        payload = str(packet_record.get("payload","") or "")
        protocol = str(packet_record.get("protocol","") or "").upper()

        for rule in self.rules:
            # optional protocol filter
            rule_proto = rule.get("protocol")
            if rule_proto and rule_proto.upper() != protocol:
                continue

            # pattern match (if present)
            pattern = rule.get("pattern")
            matched = False
            if pattern:
                try:
                    if re.search(pattern, payload, re.IGNORECASE):
                        matched = True
                except re.error:
                    # fall back to substring match if pattern is invalid
                    if pattern.lower() in payload.lower():
                        matched = True

            # TODO: threshold rules would update state; for now handle pattern rules
            if matched:
                mitre = self._normalize_mitre(rule)
                alert = {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name") or rule.get("id"),
                    "description": rule.get("description"),
                    "severity": rule.get("severity", "medium"),
                    "mitre": mitre,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "evidence": payload[:400],
                    "packet": packet_record
                }
                alerts.append(alert)
        return alerts
