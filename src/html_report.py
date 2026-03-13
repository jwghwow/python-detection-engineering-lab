from collections import Counter


def generate_html_report(alerts, output_path):
    total_alerts = len(alerts)
    critical_alerts = sum(1 for alert in alerts if alert.get("priority") == "critical")
    high_alerts = sum(1 for alert in alerts if alert.get("priority") == "high")
    unique_source_ips = len(set(alert.get("src_ip", "unknown") for alert in alerts))

    rule_counter = Counter(alert.get("rule_name", "Unknown") for alert in alerts)
    priority_counter = Counter(alert.get("priority", "unknown") for alert in alerts)
    src_ip_counter = Counter(alert.get("src_ip", "unknown") for alert in alerts)
    username_counter = Counter(
    alert.get("username", "unknown")
    for alert in alerts
    if alert.get("username")
)
    
    top_source_ips_html = ""
    for src_ip, count in src_ip_counter.most_common(10):
        top_source_ips_html += f"<li>{src_ip}: {count} alerts</li>"

    top_usernames_html = ""
    for username, count in username_counter.most_common(10):
        top_usernames_html += f"<li>{username}: {count} alerts</li>"    

    alerts_by_rule_html = ""
    for rule_name, count in rule_counter.most_common():
        alerts_by_rule_html += f"<li>{rule_name}: {count}</li>"

    alerts_by_priority_html = ""
    for priority, count in priority_counter.most_common():
        alerts_by_priority_html += f"<li>{priority}: {count}</li>"

    alert_rows_html = ""
    for alert in alerts:
        alert_id = alert.get("alert_id", "")
        rule_name = alert.get("rule_name", "")
        src_ip = alert.get("src_ip", "")
        username = alert.get("username", "")
        priority = alert.get("priority", "")
        score = alert.get("score", "")
        mitre_id = alert.get("mitre_technique_id", "")
        summary = alert.get("summary", "")

        alert_rows_html += f"""
        <tr>
            <td>{alert_id}</td>
            <td>{rule_name}</td>
            <td>{src_ip}</td>
            <td>{username}</td>
            <td>{priority}</td>
            <td>{score}</td>
            <td>{mitre_id}</td>
            <td>{summary}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Detection Lab Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 30px;
                background-color: #f4f6f8;
                color: #222;
            }}
            h1, h2 {{
                color: #1f4e79;
            }}
            .summary-container {{
                display: flex;
                gap: 20px;
                flex-wrap: wrap;
                margin-bottom: 30px;
            }}
            .summary-card {{
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                min-width: 180px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            }}
            .section {{
                background: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 25px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            }}
            ul {{
                margin: 0;
                padding-left: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
                font-size: 14px;
                background: white;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 10px;
                text-align: left;
                vertical-align: top;
            }}
            th {{
                background-color: #e8eef5;
            }}
            tr:nth-child(even) {{
                background-color: #f9fbfc;
            }}
        </style>
    </head>
    <body>
        <h1>Detection Engineering Lab Report</h1>

        <div class="summary-container">
            <div class="summary-card">
                <h2>Total Alerts</h2>
                <p>{total_alerts}</p>
            </div>
            <div class="summary-card">
                <h2>Critical Alerts</h2>
                <p>{critical_alerts}</p>
            </div>
            <div class="summary-card">
                <h2>High Alerts</h2>
                <p>{high_alerts}</p>
            </div>
            <div class="summary-card">
                <h2>Unique Source IPs</h2>
                <p>{unique_source_ips}</p>
            </div>
        </div>

        <div class="section">
            <h2>Alerts by Rule</h2>
            <ul>
                {alerts_by_rule_html}
            </ul>
        </div>

        <div class="section">
            <h2>Alerts by Priority</h2>
            <ul>
                {alerts_by_priority_html}
            </ul>
        </div>

        <div class="section">
            <h2>Top Source IPs</h2>
            <ul>
                {top_source_ips_html}
            </ul>
        </div>

        <div class="section">
            <h2>Top Targeted Usernames</h2>
            <ul>
                {top_usernames_html}
            </ul>
        </div>

        <div class="section">
            <h2>Detailed Alerts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Alert ID</th>
                        <th>Rule Name</th>
                        <th>Source IP</th>
                        <th>Username</th>
                        <th>Priority</th>
                        <th>Score</th>
                        <th>MITRE ID</th>
                        <th>Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_rows_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(html_content)