import requests
import json

url = "http://127.0.0.1:8000/alert"

payload = {
  "alert_id": "ALT-1042",
  "signature": "ET EXPLOIT Possible SQL Injection",
  "src_ip": "10.0.4.23",
  "dst_ip": "10.0.1.15",
  "dst_port": 443,
  "timestamp": "2026-09-12T10:21:32"
}

import time

print(f"Sending NIDS Alert {payload['alert_id']} to SOC API...")
start_time = time.time()
response = requests.post(url, json=payload)
end_time = time.time()
latency = end_time - start_time

if response.status_code == 200:
    print(f"\nSuccess! Request completed in {latency:.2f} seconds.")
    print("Final Graph State:")
    print(json.dumps(response.json(), indent=2))
else:
    print(f"Error: {response.status_code} (took {latency:.2f} seconds)")
    print(response.text)