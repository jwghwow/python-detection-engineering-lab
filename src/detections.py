def detect_bruteforce(events, threshold=5):
    alerts = []

    for event in events:
        if event["attempt_count"] >= threshold:
            alert = {
                "rule_name": "Brute Force Login Attempt",
                "src_ip": event["src_ip"],
                "username": event["username"],
                "hostname": event["hostname"],
                "service": event["service"],
                "attempt_count": event["attempt_count"],
                "severity": "high",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force",
                "summary": (
                    f"Source IP {event['src_ip']} made "
                    f"{event['attempt_count']} login attempts against "
                    f"user {event['username']} on {event['hostname']}."
                )
            }
            alerts.append(alert)

    return alerts

def detect_password_spray(events, threshold=5):

    alerts = []

    ip_targets = {}

    for event in events:
        ip = event["src_ip"]
        username = event["username"]

        if ip not in ip_targets:
            ip_targets[ip] = set()

        ip_targets[ip].add(username)

    for ip, usernames in ip_targets.items():

        if len(usernames) >= threshold:

            alert = {
                "rule_name": "Password Spray Attempt",
                "src_ip": ip,
                "targeted_users": list(usernames),
                "user_count": len(usernames),
                "severity": "high",
                "mitre_technique_id": "T1110.003",
                "mitre_technique_name": "Password Spraying",
                "summary": (
                    f"Source IP {ip} attempted logins against "
                    f"{len(usernames)} different accounts."
                )
            }

            alerts.append(alert)

    return alerts

def detect_privileged_account_targeting(events, privileged_users, threshold=3):
    alerts = []

    for event in events:
        username = str(event["username"]).strip().lower()

        if username in privileged_users and event["attempt_count"] >= threshold:
            alert = {
                "rule_name": "Privileged Account Targeted",
                "src_ip": event["src_ip"],
                "username": event["username"],
                "hostname": event["hostname"],
                "service": event["service"],
                "attempt_count": event["attempt_count"],
                "severity": "critical",
                "mitre_technique_id": "T1078",
                "mitre_technique_name": "Valid Accounts",
                "summary": (
                    f"Privileged account {event['username']} was targeted from "
                    f"source IP {event['src_ip']} with "
                    f"{event['attempt_count']} login attempts."
                )
            }
            alerts.append(alert)

    return alerts