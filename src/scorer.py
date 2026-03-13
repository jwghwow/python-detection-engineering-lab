def score_alert(alert):
    rule_name = alert["rule_name"]
    score = 0

    if rule_name == "Brute Force Login Attempt":
        score = 70
    elif rule_name == "Password Spray Attempt":
        score = 80
    elif rule_name == "Privileged Account Targeted":
        score = 95

    # Add bonus points for higher attempt counts
    if "attempt_count" in alert and alert["attempt_count"] >= 10:
        score += 5

    # Make sure score does not go over 100
    if score > 100:
        score = 100

    alert["score"] = score

    if score >= 90:
        alert["priority"] = "critical"
    elif score >= 75:
        alert["priority"] = "high"
    elif score >= 50:
        alert["priority"] = "medium"
    else:
        alert["priority"] = "low"

    return alert