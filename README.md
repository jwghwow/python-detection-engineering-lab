# Python Detection Engineering Lab

A Python-based cybersecurity project that simulates a lightweight **detection engineering workflow** using authentication log data sourced from Kaggle  
(`linux_auth_log-anomalies` dataset by LİN ÇORBACI).

The lab ingests CSV-based login telemetry, detects suspicious activity, enriches alerts with context and **MITRE ATT&CK mappings**, assigns severity and scores, and outputs results in **JSON, CSV, console summaries, and an HTML report**.

Previously generated example outputs are included in the `output/` directory.

---

# Features

- Brute force detection
- Password spray detection
- Privileged account targeting detection
- MITRE ATT&CK technique mapping
- Alert scoring and priority assignment
- Unique alert IDs
- JSON and CSV alert exports
- Console summary reporting
- HTML report generation

---

# Detection Rules

| Rule | Description | MITRE ATT&CK |
|-----|-----|-----|
| **Brute Force Login Attempt** | Multiple login attempts against a single account | T1110 |
| **Password Spray Attempt** | One source IP attempts logins across many usernames | T1110.003 |
| **Privileged Account Targeted** | Authentication attempts against privileged accounts | T1078 |

---

# Project Structure

```bash
detection-lab/
│
├── src/
│ ├── main.py
│ ├── parser_csv.py
│ ├── detections.py
│ ├── reporter.py
│ ├── scorer.py
│ ├── summary.py
│ ├── html_report.py
│ ├── alert_utils.py
│ └── watchlist_loader.py
│
├── watchlists/
│ └── privileged_users.json
│
├── data/
│ └── YOUR_CSV_DATASET_FROM_KAGGLE.csv
│
├── output/
│ ├── alerts.json
│ ├── alerts.csv
│ └── alerts_report.html
│
├── README.md
└── .gitignore
```

---

# Dataset

This project uses authentication log data derived from the Kaggle dataset:

**Linux Authentication Logs – Anomaly Detection**  
Author: *LİN ÇORBACI*

Dataset columns used by the project:
- timestamp
- source_ip
- server
- username
- service
- number_of_attempts


# How to Run

## 1. Clone the repository
## 2. Install Dependencies
## 3. Add the authentication log dataset
### Place your authentication log CSV file in the data/ directory.
