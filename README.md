# 🛡️ AI-Powered SOC Triage Analyst — ICMP Flood Detection POC

> A Proof of Concept demonstrating enterprise-grade **AI-powered threat detection and automated SOC triage** using **Airia AI** (platform) + **NanoGPT 5** (agent) as the SOC Triage Analyst, triggered by a real-time ICMP flood attack simulation between two VMs.

---

## 📌 Overview

This project simulates a real-world **Security Operations Center (SOC)** scenario:

1. An attacker machine (**Zorin OS VM**) launches an ICMP ping flood attack
2. The target machine (**Kali Linux**) runs a Python detection script
3. When **70+ simultaneous ICMP packets** are detected within a 5-second window, a structured JSON alert is generated
4. The alert is sent to an **AI SOC Triage Analyst** deployed on **Airia AI**, powered by **NanoGPT 5**
5. The AI follows a **professional enterprise SOC playbook** (used as its system prompt) to analyze the alert and return a full structured triage report — including threat classification, MITRE ATT&CK mapping, risk scoring, and escalation recommendation

---

## 🧱 Architecture

```
┌──────────────────────┐      ICMP Flood (40+ pkts/5s)      ┌─────────────────────────┐
│   Zorin OS VM        │  ════════════════════════════════>  │   Kali Linux (Target)   │
│   (Attacker)         │                                     │   icmp_flood_detector.py│
└──────────────────────┘                                     └────────────┬────────────┘
                                                                          │
                                                              Threshold breached →
                                                              Structured JSON alert generated
                                                                          │
                                                                          ▼
                                                             ┌────────────────────────┐
                                                             │       Airia AI         │
                                                             │  Agent: NanoGPT 5      │
                                                             │  Role: SOC Triage      │
                                                             │  (Enterprise Playbook) │
                                                             └────────────┬───────────┘
                                                                          │
                                              ┌───────────────────────────▼──────────────────────────┐
                                              │              Triage Report (JSON Output)              │
                                              │  • Threat Classification                              │
                                              │  • Risk Score (0–100) + Risk Level                    │
                                              │  • MITRE ATT&CK Tactic & Technique                   │
                                              │  • Recommended Tier 1 Actions                         │
                                              │  • Escalation Decision                                │
                                              │  • Executive Summary (plain language)                 │
                                              └───────────────────────────────────────────────────────┘
```

---

## 🧰 Tech Stack

| Component | Tool |
|---|---|
| AI Platform | [Airia AI](https://airia.ai) |
| AI Agent / Model | NanoGPT 5 (ChatGPT, via Airia AI) |
| SOC Playbook | Custom enterprise system prompt |
| Attack Source | Zorin OS VM |
| Target / Detection | Kali Linux |
| Detection Language | Python 3 |
| Packet Capture | Scapy |

---

## 📁 Project Structure

```
junior-soc-analyst-poc/
│
├── scripts/
│   └── icmp_flood_detector.py         # Detection script — runs on Kali Linux
│
├── playbooks/
│   └── soc_analyst_system_prompt.md   # Enterprise SOC playbook (Airia AI system prompt)
│
├── docs/
│   ├── setup_guide.md                 # Environment setup
│   └── attack_simulation.md           # How to simulate the ICMP flood
│
├── alerts/
│   ├── sample_alert_input.json        # Sample JSON alert sent to Airia AI agent
│   └── sample_triage_output.json      # Sample AI triage report output
│
└── README.md
```

---

## ⚙️ Setup & Usage

### Prerequisites

- Kali Linux (target/defender) with Python 3.8+ and sudo access
- Zorin OS VM (attacker) on the same network segment
- `pip install scapy requests`
- Airia AI account with NanoGPT 5 agent configured using the system prompt in `playbooks/`

### 1. Run the Detector (on Kali Linux)

```bash
sudo python3 scripts/icmp_flood_detector.py
```

### 2. Simulate the Attack (on Zorin OS VM)

```bash
# Standard flood ping
sudo ping -f -c 200 <KALI_IP>

# Or with hping3
sudo hping3 -1 --flood <KALI_IP>
```

### 3. Alert Flow

Once 70+ ICMP packets are detected within 5 seconds, the script generates a structured JSON alert and forwards it to the Airia AI SOC Analyst agent, which responds with a complete triage report.

---

## 🤖 Airia AI — SOC Triage Analyst Agent

The AI agent is configured on **Airia AI** using **NanoGPT 5** with a professional enterprise SOC system prompt that enforces:

- **Input validation** — confirms required alert fields are present
- **Threat classification** — across 6 categories (Brute Force, Recon, Suspicious Volume, etc.)
- **Risk scoring model** — 0–100 score with transparent documented logic
- **MITRE ATT&CK mapping** — tactic + technique ID + technique name
- **Tier 1 action plan** — matched to risk level (Monitor / Block / Escalate / Isolate)
- **Escalation logic** — automatic Tier 2 escalation if score ≥ 80
- **Executive summary** — plain language, business-impact focused, 2–3 sentences
- **Strict JSON-only output** — no markdown, no filler, machine-readable
- **10 security guardrails** — no attack instructions, no fabricated data, defensive only

See the full system prompt: [`playbooks/soc_analyst_system_prompt.md`](Playbooks/soc_analyst_system_prompt.md)

---

## 📊 Sample Alert Input → AI Triage Output

### Alert Input (generated by detector, sent to Airia AI)

```json
{
  "alert_id": "ICMP-1712345678",
  "alert_type": "ICMP_FLOOD",
  "indicator_type": "IP",
  "indicator_value": "192.168.56.102",
  "source_host": "zorin-vm",
  "destination_host": "kali-linux",
  "destination_ip": "192.168.56.101",
  "protocol": "ICMP",
  "evidence": {
    "packet_count": 87,
    "time_window_seconds": 5
  }
}
```

### Triage Report Output (from NanoGPT 5 via Airia AI)

```json
{
  "alert_id": "ICMP-1712345678",
  "threat_classification": "Suspicious Network Volume",
  "risk_score": 65,
  "risk_level": "High",
  "confidence_level": "High",
  "mitre_mapping": {
    "tactic": "Impact",
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service"
  },
  "analysis_reasoning": "Packet count of 87 exceeds the >50 threshold (+30). Activity occurred within a 5-second window, under 60s (+20). ICMP flood behavior confirmed (+15). Total score: 65 — classified as High.",
  "recommended_actions": [
    "Block source IP at firewall",
    "Enrich with threat intelligence",
    "Monitor for continued activity",
    "Escalate to Tier 2 analyst for review"
  ],
  "escalation_required": true,
  "executive_summary": "An unusually high volume of network traffic was detected originating from an internal machine and targeting a critical system. This pattern is consistent with a denial-of-service attempt or a seriously misconfigured device. Immediate review by the security team is recommended."
}
```

---

## 📸 Screenshots

> Add terminal screenshots and Airia AI response screenshots to a `screenshots/` folder to complete the POC demo.

---

## ⚠️ Disclaimer

This project was built entirely in a controlled lab environment using personal virtual machines. All attack simulations were performed on machines owned by the author. This project is for educational and portfolio demonstration purposes only.

---

## 👤 Author

Built as a portfolio POC for **SOC Analyst / Blue Team / Cybersecurity** roles.

**Skills demonstrated:** Network threat detection · Python scripting · AI agent integration · MITRE ATT&CK framework · SOC playbook design · Incident triage automation · Network security
