"""Simple file-based monitor that watches `logs/monitor.log` for events.

When a line containing the token "MALICIOUS" is appended, the monitor sends a
feature payload to the local pipeline endpoint to trigger anomaly detection and
automated response. This is a prototype; replace with real network ingestors
for production (pcap, Zeek logs, Netflow, etc.).
"""
import time
import os
import requests
import json

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'monitor.log')
ENDPOINT = 'http://127.0.0.1:8000/api/v1/pipeline/process'


def ensure_log():
    basedir = os.path.dirname(LOG_PATH)
    os.makedirs(basedir, exist_ok=True)
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, 'a').close()


def create_features_from_line(line: str):
    """Map a log line to a numeric feature vector (prototype).

    If the line contains 'MALICIOUS' produce an extreme vector to trigger the
    autoencoder; otherwise produce a benign vector.
    """
    if 'MALICIOUS' in line.upper():
        return [100.0] * 70
    return [0.0] * 70


LOG_EVENT_ENDPOINT = 'http://127.0.0.1:8000/api/v1/threats/log-event'

def tail_and_post():
    ensure_log()
    with open(LOG_PATH, 'r', encoding='utf-8') as fh:
        # Seek to end and start tailing
        fh.seek(0, os.SEEK_END)

        print(f"Monitoring {LOG_PATH} for events. Posting to {ENDPOINT}")

        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()
            if not line:
                continue

            features = create_features_from_line(line)
            payload = {"features": features}

            # Post to anomaly pipeline
            try:
                resp = requests.post(ENDPOINT, params={'entry_point': 'web_server', 'max_steps': 3}, json=payload, timeout=5)
                print(f"Posted pipeline event -> {resp.status_code}")
            except Exception as e:
                print(f"Pipeline post error: {e}")

            # Also directly create a threat record (log-derived) if indicators present
            try:
                rec_resp = requests.post(LOG_EVENT_ENDPOINT, json={'line': line}, timeout=5)
                if rec_resp.ok:
                    data = rec_resp.json()
                    if data.get('status') == 'created':
                        print(f"Threat created from log: {data['threat']['id']} severity={data['threat']['severity']}")
            except Exception as e:
                print(f"Log-event post error: {e}")


if __name__ == '__main__':
    tail_and_post()
