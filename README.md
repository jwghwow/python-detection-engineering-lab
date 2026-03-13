# Python Detection Engineering Lab

A Python-based cybersecurity project that simulates a lightweight detection engineering workflow using authentication log data sourced from Kaggle (linux_auth_log-anomalies from LİN ÇORBACI). The lab ingests CSV-based login telemetry, detects suspicious activity, enriches alerts with context and MITRE ATT&CK mapping, assigns severity and scores, and outputs results in JSON, CSV, console summary, and HTML report formats.  Includes previously generated output examples under the output directory.

## Features

- Brute force detection
- Password spray detection
- Privileged account targeting detection
- MITRE ATT&CK mapping
- Alert scoring and priority assignment
- Unique alert IDs
- JSON and CSV alert exports
- Console summary reporting
- HTML report generation

## Project Structure

detection-lab/
├── src/
├── watchlists/
├── data/
├── output/
├── README.md
└── .gitignore


Detection Rules

Brute Force Login Attempt → MITRE T1110
Password Spray Attempt → MITRE T1110.003
Privileged Account Targeted → MITRE T1078


How to Run

Install dependencies:
pip install pandas

Run the project:
python src/main.py


Outputs

The program generates:
alerts.json
alerts.csv
alerts_report.html

