import logging
from langchain_core.tools import tool

# Configure verbose logging for the environment simulator
logger = logging.getLogger("Zephyr-MockEnv")
logger.setLevel(logging.INFO)

# Simulated Infrastructure Registry (BGP/ASN Mocks)
BGP_REGISTRY = {
    "104.28.15.12": {"type": "CDN_EDGE", "asn": "AS13335", "owner": "Cloudflare"},
    "10.0.1.15": {"type": "INTERNAL_APP_SERVER", "asn": "PRIVATE", "owner": "Internal"},
    "10.0.4.1": {"type": "NAT_GATEWAY", "asn": "PRIVATE", "owner": "Internal"},
    "203.0.113.50": {"type": "RESIDENTIAL_ISP", "asn": "AS7018", "owner": "AT&T"}
}

@tool
def check_vulnerability(ip: str) -> str:
    """Check if the target IP has known vulnerabilities via mocked vulnerability scanner."""
    logger.info(f"Tool Execution: check_vulnerability(ip={ip})")
    
    if ip == "10.0.1.15":
        result = f"[{ip}] CVE-2021-44228 (Log4Shell): Target application is highly vulnerable."
    else:
        result = f"[{ip}] No known critical vulnerabilities found."
    
    logger.debug(f"check_vulnerability result: {result}")
    return result

@tool
def check_server_logs(incident_id: str) -> str:
    """Retrieve raw server logs associated with the incident to confirm payload execution."""
    logger.info(f"Tool Execution: check_server_logs(incident_id={incident_id})")
    
    # In full production, this triggers a vector search or pulls the block from Supabase bucket
    result = "HTTP 401: Obfuscated JNDI payload detected. Sysmon Event 1: Wget spawned from Java process on internal asset."
    
    logger.debug(f"check_server_logs result: {result}")
    return result

@tool
def simulate_blast_radius(action: str, target: str) -> str:
    """
    Near-Miss Simulation: Run by the Reviewer agent to test a proposed action against the network topology.
    This acts as the organic infrastructure guardrail.
    """
    logger.info(f"Tool Execution: simulate_blast_radius(action={action}, target={target})")
    infra = BGP_REGISTRY.get(target, {"type": "UNKNOWN", "owner": "Unknown", "asn": "Unknown"})
    
    if action == "BLOCK_SOURCE" and infra["type"] in ["CDN_EDGE", "NAT_GATEWAY"]:
        result = f"[FATAL] Action drops BGP route for {infra['owner']} ({infra['type']}). 100% loss of legitimate external traffic."
    elif action == "ISOLATE_ASSET" and infra["type"] == "INTERNAL_APP_SERVER":
        result = f"[SAFE] Internal asset isolated at VLAN level. 0% loss of external traffic. Exploit contained locally."
    elif action == "TARGETED_RULE" and infra["type"] == "CDN_EDGE":
        result = f"[SAFE] WAF rule deployed targeting specific JNDI payload pattern. Legitimate traffic unaffected."
    else:
        result = f"[UNKNOWN] Blast radius unclear for action '{action}' on infrastructure type '{infra['type']}'."
        
    logger.info(f"Blast Radius Simulation Result: {result}")
    return result

@tool
def execute_firewall_change(action: str, target: str) -> str:
    """Production Execution: Commits the approved action to the network fabric."""
    logger.info(f"Tool Execution: execute_firewall_change(action={action}, target={target})")
    
    if action in ["TARGETED_RULE", "ISOLATE_ASSET"]:
        result = f"[SUCCESS] Applied {action} to {target}. Network fabric routing updated successfully."
    else:
        # A fallback simulation rejection if a fatal action sneaks past the reviewer
        result = f"[FAILED] Command '{action}' on '{target}' rejected by master network controller due to policy violation."
        
    logger.info(f"Execution Result: {result}")
    return result

@tool
def verify_network_traffic(target: str) -> str:
    """Production Execution: Verifies if malicious outbound beaconing or exploitation has ceased."""
    logger.info(f"Tool Execution: verify_network_traffic(target={target})")
    result = f"[VERIFIED] No further malicious egress or lateral movement traffic observed on {target}. Connections reset."
    logger.debug(f"Verification Result: {result}")
    return result

# Standard toolset exposed to the Strategist agent during the Intake & Investigation phases
soc_tools = [check_vulnerability, check_server_logs]

# Note: simulate_blast_radius, execute_firewall_change, and verify_network_traffic 
# are invoked deterministically by the Reviewer, Executor, and Verifier nodes respectively.
# They are intentionally NOT included in `soc_tools` to prevent the LLM from hallucinating an early execution.