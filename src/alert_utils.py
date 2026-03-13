def assign_alert_ids(alerts):
    for index, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ALERT-{index:04d}"

    return alerts