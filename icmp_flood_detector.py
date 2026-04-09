import subprocess
import csv
import json
import os
import uuid
import requests
from collections import Counter

# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

INTERFACE = "wlan0"              # Change if needed (check with: ip a)
CAPTURE_DURATION = 100          # 5 minutes
THRESHOLD = 40                  # Packet threshold

PCAP_FILE = "/tmp/traffic.pcap"
CSV_FILE = "traffic.csv"
ALERT_FILE = "alert.json"

# ---- Airia Webhook ----
AIRIA_API_URL ="https://api.airia.ai/v2/PipelineExecution/44a6457a-0c55-4ec3-b5a9-fd2c4764b50a"
AIRIA_API_KEY ="ak-MjQ3NTQ0Nzg1MHwxNzczNDk1NzQ1MTczfHRpLVNuTjBaV05vTFU5d1pXNGdVbVZuYVhOMGNtRjBhVzl1TFVGcGNtbGhJRVp5WldVPXwxfDE0NDAxOTQ4Mzgg"

# Metadata
DESTINATION_HOST = "Internal-server"
DESTINATION_IP = "192.168.1.2"


# ------------------------------------------------
# HELPER
# ------------------------------------------------

def run_command(cmd, description):
    print(f"[+] {description}")
    subprocess.run(cmd, check=True)

# ------------------------------------------------
# STEP 1 – Capture Traffic
# ------------------------------------------------

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", "icmp and dst host 192.168.1.2", 
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    run_command(capture_cmd, f"Capturing on {INTERFACE} for {CAPTURE_DURATION}s")

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed.")

    print(f"[+] Capture saved to {PCAP_FILE}")

# ------------------------------------------------
# STEP 2 – Convert to CSV
# ------------------------------------------------

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    print(f"[+] CSV created at {CSV_FILE}")

# ------------------------------------------------
# STEP 3 – Analyze Traffic
# ------------------------------------------------

def analyze_traffic():
    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    print("\n[+] Traffic volume per source IP:\n")
    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")

    # Return first suspicious IP found
    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            print(f"\n[!] Suspicious IP detected: {ip}")
            return ip, count

    print("\n[+] No suspicious activity detected.")
    return None, None
# ------------------------------------------------
# STEP 4 – Generate Alert JSON
# ------------------------------------------------

def generate_alert(ip, count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "alert_type": "Suspicious Network Volume",
        "indicator_type": "ip",
        "indicator_value": ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "evidence": {
            "packet_count": count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },
        "analyst_question": "Is this expected activity or suspicious scanning/noise?"
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"[+] Alert JSON written to {ALERT_FILE}")
    return alert

# ------------------------------------------------
# STEP 5 – Send to Airia API
# ------------------------------------------------

def send_to_airia(alert):

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": AIRIA_API_KEY
    }

    payload = {
        "UserInput": json.dumps(alert),   # REQUIRED FIELD
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia Agent Execution API...")

    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json=payload,
        timeout=100
    )

    print("Status Code:", response.status_code)
    print("Response:", response.text)
# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    try:
        capture_traffic()
        convert_to_csv()
        ip, count = analyze_traffic()

        if ip:
            alert = generate_alert(ip, count)
            send_to_airia(alert)
        else:
            print("[+] No alert generated, nothing sent to Airia.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
