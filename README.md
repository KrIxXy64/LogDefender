 LogDefender – Automated Log Analysis & Incident Detection Tool

A lightweight yet powerful Python-based security monitoring tool designed to detect suspicious activities such as brute-force attacks, unauthorized logins, port scans, privilege escalations, and persistence mechanisms through cron jobs.

⸻

🚀 Project Overview

LogDefender analyzes Linux authentication logs (auth.log) and identifies patterns commonly associated with cyber attacks.
The tool is designed for beginners, SOC analysts, blue teamers, and students who want hands-on experience with:
	•	Log parsing
	•	Attack pattern detection
	•	Python automation
	•	Building security tools

This project simulates how real SIEM and IDS systems work.

⸻

✨ Key Features

🔐 Authentication Attack Detection
	•	Brute-force attempts
	•	Suspicious successful logins
	•	Unauthorized sudo attempts

👤 Persistence & Privilege Monitoring
	•	New user account creation
	•	Cron-job abuse (root cron sessions)

🔭 Network Recon Detection
	•	Port scanning detection
	•	Identifies an IP probing multiple ports
	•	Uses threshold-based correlation technique

📄 Reporting
	•	Saves alerts in:reports/alerts.txt
	•	Prints alerts to the terminal

📦 Organized Project Structure
LogDefender/
 ├── logs/
 │   └── auth.log
 ├── scripts/
 │   └── detector.py
 ├── reports/
 │   └── alerts.txt
 ├── venv/
 └── README.md
🛠️ Installation

1️⃣ Clone  the Repositorgit clone https://github.com/KrIxXY64/LogDefender.git
cd LogDefendery
Set Up Virtual Environment python3 -m venv venv
source venv/bin/activate

 Ensure Logs Exist
Place your logs inside:logs/auth.log
Sample logs are provided for testing.


python scripts/detector.py

outputs:
[ALERT] Brute-force attempt detected from IP: 192.168.1.23
[ALERT] Suspicious login success from 185.199.110.12
[ALERT] Unauthorized sudo attempt detected.
[ALERT] New user creation found: ...
[ALERT] Possible PORT SCAN detected from IP: 45.122.88.12

reports/alerts.txt
Supported Detection Rules

Brute-force Attack
Multiple failed login attempts from same IP
Suspicious Login
Accepted password from unusual IP
Unauthorized Sudo
Privilege escalation failures
New User Creation
Potential persistence mechanism
Cron Abuse
Suspicious root cron sessions
Port Scan Detection
>5 unique ports probed by a single IP


Sample Log Entries Used for Testing

Brute-force:Failed password for invalid user admin from 192.168.1.23 port 51322 ssh2

Port scan simulation:Connection attempt from 45.122.88.12 port 21
Connection attempt from 45.122.88.12 port 22
Connection attempt from 45.122.88.12 port 23
Connection attempt from 45.122.88.12 port 25
Connection attempt from 45.122.88.12 port 80
Connection attempt from 45.122.88.12 port 443


How Port Scan Detection Works

LogDefender tracks how many unique ports an IP touches.

If more than 5 distinct ports are probed, the tool raises:[ALERT] Possible PORT SCAN detected from IP: x.x.x.x


This mimics behavior of real SIEM correlation engines.

Future Enhancements
	•	Live monitoring mode (tail -f style)
	•	JSON alert output for SIEM integration
	•	Email/Slack alerting
	•	Web dashboard visualization
	•	Integrate firewall auto-blocking
	•	Add machine learning anomaly detection


Developer

S.Saarthak Singh Dangi
Cybersecurity Student – Medicaps University Indore
Project built for learning, SOC skill development, and career portfolio enhancement.  


 Disclaimer

This project is intended for educational and defensive purposes only.
Do not use LogDefender on systems you do not own or have permission to monitor.
