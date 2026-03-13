from html_report import generate_html_report
from summary import print_alert_summary
from parser_csv import parse_auth_csv
from scorer import score_alert
import detections
from reporter import write_alerts_to_json, write_alerts_to_csv
from watchlist_loader import load_privileged_users
from alert_utils import assign_alert_ids


def main():
    input_file = "../data/auth_logs.csv"
    json_output_file = "../output/alerts.json"
    csv_output_file = "../output/alerts.csv"
    privileged_users_file = "../watchlists/privileged_users.json"
    html_output_file = "../output/alerts_report.html"
    

    events = parse_auth_csv(input_file)
    print(f"Loaded {len(events)} events")

    privileged_users = load_privileged_users(privileged_users_file)
    print(f"Loaded {len(privileged_users)} privileged users")

    alerts = []

    alerts.extend(detections.detect_bruteforce(events, threshold=5))
    alerts.extend(detections.detect_password_spray(events, threshold=5))
    alerts.extend(
        detections.detect_privileged_account_targeting(
            events,
            privileged_users,
            threshold=3
        )
    )

    scored_alerts = []

    for alert in alerts:
        scored_alert = score_alert(alert)
        scored_alerts.append(scored_alert)
        
    final_alerts = assign_alert_ids(scored_alerts)

    print(f"Generated {len(final_alerts)} alerts")

    print_alert_summary(final_alerts)
    
    write_alerts_to_json(final_alerts, json_output_file)
    write_alerts_to_csv(final_alerts, csv_output_file)
    generate_html_report(final_alerts, html_output_file)

    print(f"Alerts written to {json_output_file}")
    print(f"Alerts written to {csv_output_file}")
    generate_html_report(final_alerts, html_output_file)


if __name__ == "__main__":
    main()