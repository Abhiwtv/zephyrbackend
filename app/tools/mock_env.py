from langchain_core.tools import tool

@tool
def check_vulnerability(ip: str) -> str:
    """Check if the target IP has known vulnerabilities."""
    if ip == "10.0.1.15":
        return f"[{ip}] CVE-2023-XXXX: Target application is vulnerable to SQL Injection."
    return f"[{ip}] No known vulnerabilities found."

@tool
def check_server_logs(ip: str) -> str:
    """Retrieve server logs for the target IP to confirm payload execution."""
    if ip == "10.0.1.15":
        return f"[{ip}] HTTP 200 GET /search?q=' OR 1=1 -- ; DATABASE ERROR: syntax error."
    return f"[{ip}] No unusual logs found."

# List of tools to bind to the LLM
soc_tools = [check_vulnerability, check_server_logs]

# Add these below your existing tools in app/tools/mock_env.py

@tool
def simulate_firewall(action: str, target: str) -> str:
    """Execute the approved mitigation action in the sandbox."""
    if action == "TARGETED_RULE" and target == "10.0.4.23":
        return f"[SUCCESS] Applied WAF rule dropping SQLi payloads from {target}."
    return f"[FAILED] Action {action} on {target} was blocked or unrecognized."

@tool
def verify_network_traffic(target: str) -> str:
    """Check if malicious traffic is still reaching the target after mitigation."""
    return f"[VERIFIED] No further malicious SQLi traffic observed from {target}. Application is stable."

