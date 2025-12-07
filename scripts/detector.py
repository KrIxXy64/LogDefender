import re
from datetime import datetime
from pathlib import Path

LOG_PATH = "logs/auth.log"
REPORT_PATH = "reports/alerts.txt"

class LogDefender:

    def __init__(self):
        self.alerts = []
        self.port_scan_attempts = {}   # Store ports hit by each IP for port scan detection

    # ---------------------- DETECTION RULES ----------------------

    def detect_bruteforce(self, line):
        if "Failed password" in line:
            ip = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if ip:
                alert = f"[ALERT] Brute-force attempt detected from IP: {ip.group(1)}"
                self.alerts.append(alert)

    def detect_suspicious_login(self, line):
        if "Accepted password" in line:
            ip = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if ip:
                alert = f"[ALERT] Suspicious login success from {ip.group(1)}"
                self.alerts.append(alert)

    def detect_new_user(self, line):
        if "useradd" in line or "new user" in line:
            alert = f"[ALERT] New user creation found: {line.strip()}"
            self.alerts.append(alert)

    def detect_sudo_failure(self, line):
        if "sudo" in line and "authentication failure" in line:
            alert = "[ALERT] Unauthorized sudo attempt detected."
            self.alerts.append(alert)

    def detect_cron_abuse(self, line):
        if "CRON" in line and "session opened for user root" in line:
            alert = "[ALERT] Suspicious root cron job execution detected."
            self.alerts.append(alert)

    def detect_port_scan(self, line):
        """
        Detects possible port scanning by tracking multiple ports hit by same IP.
        If an IP attempts > 5 different ports → possible port scan
        """
        ip_match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        port_match = re.search(r"port (\d+)", line)

        if ip_match and port_match:
            ip = ip_match.group(1)
            port = port_match.group(1)

            # Track ports accessed by each IP
            if ip not in self.port_scan_attempts:
                self.port_scan_attempts[ip] = set()

            self.port_scan_attempts[ip].add(port)

            # Threshold: if IP hits > 5 unique ports → port scan
            if len(self.port_scan_attempts[ip]) > 5:
                alert = f"[ALERT] Possible PORT SCAN detected from IP: {ip}"
                if alert not in self.alerts:  # prevent duplicates
                    self.alerts.append(alert)

    # ---------------------- MAIN ENGINE ----------------------

    def run_detection(self):
        if not Path(LOG_PATH).exists():
            print("Log file not found.")
            return

        with open(LOG_PATH, "r") as file:
            for line in file:
                self.detect_bruteforce(line)
                self.detect_suspicious_login(line)
                self.detect_new_user(line)
                self.detect_sudo_failure(line)
                self.detect_cron_abuse(line)
                self.detect_port_scan(line)

        self.save_report()

    # ---------------------- SAVE ALERTS ----------------------

    def save_report(self):
        with open(REPORT_PATH, "w") as f:
            for alert in self.alerts:
                f.write(alert + "\n")

        print("\nAlerts generated and saved in reports/alerts.txt\n")
        for alert in self.alerts:
            print(alert)


# ---------------------- ENTRY POINT ----------------------

if __name__ == "__main__":
    detector = LogDefender()
    detector.run_detection()
