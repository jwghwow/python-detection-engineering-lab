from collections import Counter


def print_alert_summary(alerts):
    print("\nDetection Summary")
    print("-" * 40)

    total_alerts = len(alerts)
    print(f"Total alerts: {total_alerts}")

    rule_counter = Counter()
    priority_counter = Counter()
    src_ip_counter = Counter()

    for alert in alerts:
        rule_counter[alert["rule_name"]] += 1
        priority_counter[alert["priority"]] += 1
        src_ip_counter[alert["src_ip"]] += 1

    print("\nAlerts by rule:")
    for rule_name, count in rule_counter.items():
        print(f"- {rule_name}: {count}")

    print("\nAlerts by priority:")
    for priority, count in priority_counter.items():
        print(f"- {priority}: {count}")

    print("\nTop source IPs:")
    for src_ip, count in src_ip_counter.most_common(5):
        print(f"- {src_ip}: {count} alerts")