import json
import csv


def write_alerts_to_json(alerts, output_path):
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)


def write_alerts_to_csv(alerts, output_path):
    if not alerts:
        return

    cleaned_alerts = []

    for alert in alerts:
        cleaned_alert = {}

        for key, value in alert.items():
            if isinstance(value, list):
                cleaned_alert[key] = "; ".join(str(item) for item in value)
            else:
                cleaned_alert[key] = value

        cleaned_alerts.append(cleaned_alert)

    fieldnames = set()
    for alert in cleaned_alerts:
        fieldnames.update(alert.keys())

    fieldnames = list(fieldnames)

    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cleaned_alerts)