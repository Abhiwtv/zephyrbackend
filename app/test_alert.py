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

print(f"Sending NIDS Alert {payload['alert_id']} to SOC API...")
response = requests.post(url, json=payload)

if response.status_code == 200:
    print("\n✅ Success! Final Graph State:")
    print(json.dumps(response.json(), indent=2))
else:
    print(f"❌ Error: {response.status_code}")
    print(response.text)