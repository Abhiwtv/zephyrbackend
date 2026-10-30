import time
import requests
from scapy.all import sniff, TCP, IP

# Change localhost to host.docker.internal
FASTAPI_URL = "http://host.docker.internal:8000/api/v1/alert"

NODE_IP_MAP = {
    "172.28.0.11": "pc-1",
    "172.28.0.12": "pc-2",
    "172.28.0.13": "pc-3",
    "172.28.0.14": "pc-4",
    "172.28.0.15": "pc-5"
}

def analyze_window(packets, window_start):
    if not packets:
        return

    # Track base metrics
    total_bytes = sum(len(p) for p in packets)
    tcp_packets = [p for p in packets if p.haslayer(TCP) and p.haslayer(IP)]
    
    if not tcp_packets:
        return

    # Calculate SYN ratio
    syn_packets = [p for p in tcp_packets if p[TCP].flags == "S"]
    syn_ratio = len(syn_packets) / len(tcp_packets)
    unique_ports = list(set(p[TCP].dport for p in tcp_packets))
    
    print(f"[Sensor] Window analyzed: {len(packets)} packets | SYN Ratio: {syn_ratio:.2f}")

    # Heuristic Trigger: >1000 packets/window AND >60% are SYN requests
    if len(packets) > 1000 and syn_ratio > 0.60:
        print(f"\n[!] SYN FLOOD DETECTED ({len(packets)} packets). Dispatching to Zephyr LLM...")
        
        # Extract the primary attacker and victim from the traffic spike
        freq_packet = max(syn_packets, key=lambda p: syn_packets.count(p))
        src_ip = freq_packet[IP].src
        dst_ip = freq_packet[IP].dst
        port = freq_packet[TCP].dport
        
        # Build the exact schema-compliant payload required by state.py
        alert_payload = {
            "alert_id": f"evt-{int(time.time())}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_node": NODE_IP_MAP.get(src_ip, "pc-2"), # Fallback if IP spoofed outside subnet
            "source_ip": src_ip,
            "target_node": NODE_IP_MAP.get(dst_ip, "pc-4"),
            "target_ip": dst_ip,
            "dest_port": port,
            "protocol": "TCP",
            "flow_metrics": {
                "packet_count_2s": len(packets),
                "byte_count_2s": total_bytes,
                "syn_ratio": round(syn_ratio, 2),
                "unique_dest_ports": unique_ports,
                "payload_sample": "02 04 05 b4 04 02 08 0a" # Hex sample placeholder
            },
            "nids_llm_assessment": {
                "attack_signature": "TCP_SYN_FLOOD",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1498",
                "confidence_score": 0.98,
                "severity": "HIGH",
                "raw_telemetry_summary": f"Sensor threshold breached: {len(packets)} packets detected in 2s with {syn_ratio*100:.1f}% SYN flag ratio targeting {dst_ip}:{port}."
            }
        }
        
        try:
            res = requests.post(FASTAPI_URL, json=alert_payload)
            # DUMP THE RAW TEXT to see exactly what FastAPI rejected
            print(f"[+] FastAPI Raw Response: {res.text}\n")
        except Exception as e:
            print(f"[-] Backend connection failed: {e}\n")

def run_sensor():
    print("Starting Scapy Sensor on Docker Bridge (Ctrl+C to stop)...")
    while True:
        window_start = time.time()
        # Explicitly bind to eth0 if running inside the Docker network namespace
        packets = sniff(iface="eth0", filter="net 172.28.0.0/16", timeout=2)
        analyze_window(packets, window_start)

if __name__ == "__main__":
    run_sensor()