"""
#!/usr/bin/env python
ICMP Flood Detection Script
============================
Target Machine  : Kali Linux
Attacker Machine: Zorin OS VM
Threshold       : 70+ ICMP packets within 5 seconds
On detection    : Generates a structured JSON alert and forwards it
                  to Airia AI (NanoGPT 5 — SOC Triage Analyst agent)

Author: SOC Analyst POC Project
"""

import json
import time
import socket
import logging
import datetime
import threading
from collections import defaultdict
from scapy.all import sniff, IP, ICMP

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
THRESHOLD          = 70             # ICMP packet count to trigger alert
TIME_WINDOW        = 5              # Detection window in seconds
INTERFACE          = None           # e.g. "eth0" — None = auto-detect
ALERT_LOG_FILE     = "alerts/alert_log.json"

# Airia AI webhook — paste your endpoint URL here
AIRIA_WEBHOOK_URL  = ""             # e.g. "https://app.airia.ai/webhooks/your-id"

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("alerts/detection.log")
    ]
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  State
# ─────────────────────────────────────────────
packet_tracker = defaultdict(list)   # { src_ip: [timestamps] }
alerted_ips    = set()               # Cooldown: avoid duplicate alerts


# ─────────────────────────────────────────────
#  Alert Generation
# ─────────────────────────────────────────────
def build_alert(src_ip: str, packet_count: int) -> dict:
    """
    Build a structured JSON alert that matches the required input
    schema expected by the Airia AI SOC Triage Analyst playbook.
    """
    return {
        "alert_id":        f"ICMP-{int(time.time())}",
        "alert_type":      "ICMP_FLOOD",
        "indicator_type":  "IP",
        "indicator_value": src_ip,
        "source_host":     resolve_hostname(src_ip),
        "destination_host": socket.gethostname(),
        "destination_ip":  get_local_ip(),
        "protocol":        "ICMP",
        "timestamp":       datetime.datetime.utcnow().isoformat() + "Z",
        "evidence": {
            "packet_count":         packet_count,
            "time_window_seconds":  TIME_WINDOW
        }
    }


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────
#  Alert Dispatch
# ─────────────────────────────────────────────
def save_alert(alert: dict):
    """Append alert JSON to local log file."""
    try:
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
        log.info(f"[+] Alert saved → {ALERT_LOG_FILE}")
    except Exception as e:
        log.error(f"Failed to save alert: {e}")


def send_to_airia(alert: dict):
    """
    Forward the alert to the Airia AI SOC Triage Analyst agent.
    The agent (NanoGPT 5) will process it against the SOC playbook
    and return a structured triage report.
    """
    if not AIRIA_WEBHOOK_URL:
        log.warning("[!] AIRIA_WEBHOOK_URL not set — skipping AI dispatch.")
        return

    try:
        import requests
        response = requests.post(
            AIRIA_WEBHOOK_URL,
            json=alert,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            log.info(f"[+] Alert dispatched to Airia AI — HTTP {response.status_code}")
            triage = response.json()
            print_triage_report(triage)
        else:
            log.warning(f"[!] Airia AI returned HTTP {response.status_code}: {response.text}")
    except Exception as e:
        log.error(f"Failed to send alert to Airia AI: {e}")


def print_triage_report(report: dict):
    """Pretty-print the AI triage report to terminal."""
    print("\n" + "═" * 62)
    print("🤖  AIRIA AI — SOC TRIAGE REPORT")
    print("═" * 62)
    print(f"  Alert ID           : {report.get('alert_id', 'N/A')}")
    print(f"  Classification     : {report.get('threat_classification', 'N/A')}")
    print(f"  Risk Score         : {report.get('risk_score', 'N/A')} / 100")
    print(f"  Risk Level         : {report.get('risk_level', 'N/A')}")
    print(f"  Confidence         : {report.get('confidence_level', 'N/A')}")
    mitre = report.get("mitre_mapping", {})
    print(f"  MITRE ATT&CK       : {mitre.get('technique_id')} — {mitre.get('technique_name')}")
    print(f"  Escalation Needed  : {report.get('escalation_required', 'N/A')}")
    print(f"  Executive Summary  : {report.get('executive_summary', 'N/A')}")
    actions = report.get("recommended_actions", [])
    if actions:
        print("  Recommended Actions:")
        for a in actions:
            print(f"    • {a}")
    print("═" * 62 + "\n")


# ─────────────────────────────────────────────
#  Alert Trigger
# ─────────────────────────────────────────────
def trigger_alert(src_ip: str, packet_count: int):
    alert = build_alert(src_ip, packet_count)

    print("\n" + "═" * 62)
    print("🚨  ICMP FLOOD DETECTED — ALERT TRIGGERED")
    print("═" * 62)
    print(f"  Alert ID      : {alert['alert_id']}")
    print(f"  Source IP     : {alert['indicator_value']}")
    print(f"  Source Host   : {alert['source_host']}")
    print(f"  Packet Count  : {packet_count} in {TIME_WINDOW}s  (threshold: {THRESHOLD})")
    print(f"  Timestamp     : {alert['timestamp']}")
    print(f"  → Forwarding to Airia AI SOC Triage Analyst...")
    print("═" * 62 + "\n")

    save_alert(alert)
    send_to_airia(alert)

    # Reset cooldown for this IP after 30 seconds
    def reset_cooldown(ip):
        time.sleep(30)
        alerted_ips.discard(ip)

    threading.Thread(target=reset_cooldown, args=(src_ip,), daemon=True).start()


# ─────────────────────────────────────────────
#  Packet Processing
# ─────────────────────────────────────────────
def process_packet(packet):
    if IP in packet and ICMP in packet:
        src_ip = packet[IP].src
        now    = time.time()

        packet_tracker[src_ip].append(now)

        # Prune timestamps outside the time window
        packet_tracker[src_ip] = [
            ts for ts in packet_tracker[src_ip]
            if now - ts <= TIME_WINDOW
        ]

        count = len(packet_tracker[src_ip])

        if count >= THRESHOLD and src_ip not in alerted_ips:
            alerted_ips.add(src_ip)
            trigger_alert(src_ip, count)
        elif count > 20:
            log.debug(f"[MONITOR] {src_ip} → {count} ICMP packets in last {TIME_WINDOW}s")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    print("""
╔════════════════════════════════════════════════════════════╗
║       AI-Powered SOC Triage — ICMP Flood Detector         ║
║       Platform : Airia AI  |  Agent : NanoGPT 5           ║
║       Target   : Kali Linux                               ║
╚════════════════════════════════════════════════════════════╝
    """)
    log.info(f"[*] Detection threshold : {THRESHOLD} packets / {TIME_WINDOW}s")
    log.info(f"[*] Interface           : {INTERFACE or 'auto-detect'}")
    log.info(f"[*] Airia AI endpoint   : {AIRIA_WEBHOOK_URL or 'NOT CONFIGURED'}")
    log.info("[*] Listening for ICMP traffic... Press Ctrl+C to stop.\n")

    try:
        sniff(
            filter="icmp",
            prn=process_packet,
            store=False,
            iface=INTERFACE
        )
    except KeyboardInterrupt:
        log.info("\n[!] Detector stopped.")
    except PermissionError:
        log.error("[ERROR] Root required — run: sudo python3 icmp_flood_detector.py")


if __name__ == "__main__":
    main()
