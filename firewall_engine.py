"""
firewall_engine.py
Core stateless packet-filtering engine.
"""

import ipaddress
import json
import os
from datetime import datetime

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")
LOG_FILE   = os.path.join(os.path.dirname(__file__), "firewall.log")

# ──────────────────────────────────────────────
# Rule schema
# ──────────────────────────────────────────────
DEFAULT_RULES = [
    {"id": 1, "priority": 1, "src_ip": "192.168.1.5", "dest_port": "ANY",
     "protocol": "ANY", "direction": "ANY", "action": "BLOCK",
     "description": "Block all traffic from 192.168.1.5"},
    {"id": 2, "priority": 2, "src_ip": "ANY", "dest_port": "80",
     "protocol": "TCP", "direction": "INBOUND", "action": "ALLOW",
     "description": "Allow HTTP inbound"},
    {"id": 3, "priority": 3, "src_ip": "ANY", "dest_port": "23",
     "protocol": "TCP", "direction": "ANY", "action": "BLOCK",
     "description": "Block Telnet"},
    {"id": 4, "priority": 4, "src_ip": "10.0.0.0/8", "dest_port": "ANY",
     "protocol": "ANY", "direction": "ANY", "action": "ALLOW",
     "description": "Allow internal subnet 10.0.0.0/8"},
    {"id": 5, "priority": 5, "src_ip": "ANY", "dest_port": "ANY",
     "protocol": "ANY", "direction": "ANY", "action": "ALLOW",
     "description": "Default allow-all"},
]


# ──────────────────────────────────────────────
# Persistence helpers
# ──────────────────────────────────────────────
def load_rules() -> list[dict]:
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    save_rules(DEFAULT_RULES)
    return list(DEFAULT_RULES)


def save_rules(rules: list[dict]) -> None:
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


# ──────────────────────────────────────────────
# Matching helpers
# ──────────────────────────────────────────────
def _match_ip(rule_ip: str, packet_ip: str) -> bool:
    """Return True if packet_ip matches the rule's IP/CIDR."""
    if rule_ip.upper() == "ANY":
        return True
    try:
        if "/" in rule_ip:
            return ipaddress.ip_address(packet_ip) in ipaddress.ip_network(rule_ip, strict=False)
        return ipaddress.ip_address(rule_ip) == ipaddress.ip_address(packet_ip)
    except ValueError:
        return False


def _match_port(rule_port: str, packet_port: str) -> bool:
    if rule_port.upper() == "ANY":
        return True
    try:
        return int(rule_port) == int(packet_port)
    except ValueError:
        return False


def _match_field(rule_val: str, packet_val: str) -> bool:
    if rule_val.upper() == "ANY":
        return True
    return rule_val.upper() == str(packet_val).upper()


# ──────────────────────────────────────────────
# Core engine
# ──────────────────────────────────────────────
class FirewallEngine:
    def __init__(self):
        self.rules: list[dict] = load_rules()
        self.default_policy: str = "BLOCK"   # ALLOW or BLOCK

    # ── Rule management ──────────────────────
    def add_rule(self, rule: dict) -> None:
        existing_ids = {r["id"] for r in self.rules}
        rule["id"] = max(existing_ids, default=0) + 1
        self.rules.append(rule)
        self._sort_rules()
        save_rules(self.rules)

    def delete_rule(self, rule_id: int) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r["id"] != rule_id]
        save_rules(self.rules)
        return len(self.rules) < before

    def update_rule(self, rule_id: int, updated: dict) -> bool:
        for i, r in enumerate(self.rules):
            if r["id"] == rule_id:
                updated["id"] = rule_id
                self.rules[i] = updated
                self._sort_rules()
                save_rules(self.rules)
                return True
        return False

    def _sort_rules(self):
        self.rules.sort(key=lambda r: r.get("priority", 9999))

    def reload(self):
        self.rules = load_rules()

    # ── Packet evaluation ────────────────────
    def evaluate(self, packet: dict) -> dict:
        """
        Evaluate a packet dict and return a verdict dict.

        packet keys: src_ip, dest_ip, src_port, dest_port, protocol, direction
        """
        matched_rule = None
        for rule in sorted(self.rules, key=lambda r: r.get("priority", 9999)):
            if (
                _match_ip(rule["src_ip"], packet["src_ip"])
                and _match_port(rule["dest_port"], packet["dest_port"])
                and _match_field(rule["protocol"], packet["protocol"])
                and _match_field(rule["direction"], packet["direction"])
            ):
                matched_rule = rule
                break

        if matched_rule:
            action  = matched_rule["action"].upper()
            matched = f"Rule #{matched_rule['priority']} — {matched_rule.get('description','')}"
        else:
            action  = self.default_policy
            matched = f"No rule matched → Default policy ({self.default_policy})"

        verdict = {
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action":       action,
            "matched_rule": matched,
            "packet":       packet,
        }
        self._log(verdict)
        return verdict

    # ── Logging ──────────────────────────────
    def _log(self, verdict: dict) -> None:
        p = verdict["packet"]
        src_host = p.get("src_host", p["src_ip"])
        dest_host = p.get("dest_host", p["dest_ip"])
        src_label = (f"{p['src_ip']} ({src_host})"
                     if src_host != p["src_ip"] else p["src_ip"])
        dest_label = (f"{p['dest_ip']} ({dest_host})"
                      if dest_host != p["dest_ip"] else p["dest_ip"])
        line = (
            f"[{verdict['timestamp']}] {verdict['action']:5s} | "
            f"{src_label}:{p['src_port']} -> {dest_label}:{p['dest_port']} "
            f"| {p['protocol']:5s} | {p['direction']:8s} | {verdict['matched_rule']}\n"
        )
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

    def get_log_entries(self, n: int = 200) -> list[str]:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return lines[-n:]

    def clear_log(self) -> None:
        open(LOG_FILE, "w").close()
