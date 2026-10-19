import requests
import json
import time
import sys

def run_sse_stress_test():
    url = "http://127.0.0.1:8000/api/simulate-attack/stream"
    payload = {
        "incident_id": "STRESS-TEST-001",
        "signature": "ET EXPLOIT Possible SQL Injection",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.1.15"
    }

    print("🔌 Connecting to Zephyr SSE Stream...")
    start_time = time.time()
    
    try:
        # stream=True keeps the connection open for SSE
        with requests.post(url, json=payload, stream=True) as response:
            response.raise_for_status()
            
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode('utf-8')
                    if decoded_line.startswith("data: "):
                        # Parse the JSON payload emitted by main.py
                        data = json.loads(decoded_line[6:])
                        node = data.get("node", "UNKNOWN")
                        status = data.get("status", "")
                        elapsed = time.time() - start_time
                        
                        # Console formatting for visibility
                        if status == "connected":
                            print(f"\n[{elapsed:.1f}s] ✅ {data['message']}")
                        elif status == "terminated":
                            print(f"\n[{elapsed:.1f}s] 🏁 {data['message']}")
                        else:
                            flag = data.get('internal_status_flag', 'COMPLETED')
                            action = data.get('action_proposed', 'N/A')
                            print(f"[{elapsed:.1f}s] ⚙️  Node Finished: {node.upper()}")
                            print(f"       Status: {flag}")
                            if action != "N/A" and action is not None:
                                print(f"       Action Proposed: {action} on {data.get('target', 'N/A')}")
                                
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Is the FastAPI server running on port 10000?")
    except Exception as e:
        print(f"❌ Stream interrupted: {str(e)}")

if __name__ == "__main__":
    run_sse_stress_test()