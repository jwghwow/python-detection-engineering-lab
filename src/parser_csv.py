import pandas as pd


def parse_auth_csv(file_path):
    df = pd.read_csv(file_path)

    events = []

    for _, row in df.iterrows():
        event = {
            "timestamp": row["timestamp"],
            "src_ip": row["source_ip"],
            "hostname": row["server"],
            "username": row["username"],
            "service": row["service"],
            "attempt_count": int(row["attempts"]),
            "status": row["status"],
            "port": row["port"],
            "protocol": row["port"],
            "comment": row["comment"],
            "anomaly_label": row["anomaly_label"],
            "delta_t": row["delta_t"]
        }
        events.append(event)

    return events