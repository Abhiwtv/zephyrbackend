import os
import json
import logging
import ipaddress
from langchain_core.tools import tool
from dotenv import load_dotenv

# LangChain & Supabase JIT Query Imports
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_openai import OpenAIEmbeddings
from supabase import create_client, Client

load_dotenv()

# Configure verbose logging for the environment simulator
logger = logging.getLogger("Zephyr-MockEnv")
logger.setLevel(logging.INFO)

# ==========================================
# MASTER ASSET INVENTORY (DYNAMIC LOAD)
# ==========================================
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
INVENTORY_FILE = os.path.join(DATA_DIR, "asset_inventory.json")

def load_inventory() -> dict:
    if not os.path.exists(INVENTORY_FILE):
        logger.error(f"[FATAL] Inventory file missing at {INVENTORY_FILE}. Run generate_dataset.py first.")
        raise FileNotFoundError(f"Missing {INVENTORY_FILE}")
    try:
        with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[FATAL] Failed to parse asset inventory: {e}")
        raise

ASSET_INVENTORY = load_inventory()

def resolve_asset(ip_string: str) -> dict:
    """
    Core Engine Router: Validates an IP against the Asset Inventory.
    Enforces Fail-Loud for missing internal assets to prevent silent dataset drift.
    """
    if ip_string in ASSET_INVENTORY:
        return ASSET_INVENTORY[ip_string]
        
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        # Catch RFC 1918, Loopback, Link-Local (e.g. AWS IMDS 169.254.x.x)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise KeyError(f"Pipeline Fatal Error: Internal/Reserved IP {ip_string} missing from ASSET_INVENTORY.")
        else:
            # Default-Approve logic for rogue external IP addresses
            return {
                "asset_name": "Unknown External Entity", 
                "criticality_tier": 4, 
                "business_function": "Untrusted Public Internet"
            }
    except ValueError:
        # Failsafe for malformed strings or MAC addresses (e.g., Rogue APs)
        return {
            "asset_name": "Non-Standard/MAC Identifier", 
            "criticality_tier": 4, 
            "business_function": "Unregistered Device"
        }

# ==========================================
# SIMULATION TOOLS
# ==========================================

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
    """Retrieve raw server logs associated with the incident via live Supabase Vector Search."""
    logger.info(f"Tool Execution: check_server_logs(incident_id={incident_id})")
    
    try:
        supabase_url = os.environ.get("SUPABASE_URL")
        supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
        
        if not supabase_url or not supabase_key:
            return "[ERROR] Supabase credentials missing. Cannot execute vector search."

        supabase: Client = create_client(supabase_url, supabase_key)
        embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        vector_store = SupabaseVectorStore(
            client=supabase, 
            embedding=embeddings, 
            table_name="documents", 
            query_name="match_documents"
        )
        
        # Execute a metadata-filtered similarity search for the exact JIT-embedded document
        docs = vector_store.similarity_search(
            query="Extract malicious telemetry", 
            filter={"incident_id": incident_id},
            k=1
        )
        
        if docs:
            return docs[0].metadata.get("full_timeline", "Timeline missing in metadata.")
        else:
            return f"[ERROR] No SIEM logs found in vector database for {incident_id}."
            
    except Exception as e:
        logger.error(f"Vector search failed: {e}")
        return f"[ERROR] SIEM query failed: {str(e)}"

@tool
def simulate_blast_radius(action: str, target: str) -> str:
    """
    Near-Miss Simulation: Run by the Reviewer agent to test a proposed action against the CMDB topology.
    Acts as the deterministic RART guardrail.
    """
    logger.info(f"Tool Execution: simulate_blast_radius(action={action}, target={target})")
    
    infra = resolve_asset(target)
    tier = infra["criticality_tier"]
    
    if tier == 1:
        if action in ["BLOCK_SOURCE", "ISOLATE_ASSET", "DISABLE_ADAPTER", "REBOOT_SYSTEM"]:
            result = f"[REJECTED] Target is Tier 1 ({infra['asset_name']}). Proposed action '{action}' violates availability SLA. Suggest granular API revocation, WAF targeting, or failover first."
        else:
            result = f"[APPROVED] Action '{action}' passes Tier 1 safety checks."
            
    elif tier == 2:
        if action in ["REBOOT_SYSTEM", "WIPE_DISK", "DELETE_FILE"]:
            result = f"[REJECTED] Target is Tier 2 ({infra['asset_name']}). Proposed action '{action}' violates data persistence/uptime constraints. Suggest isolation instead."
        else:
            result = f"[APPROVED] Action '{action}' passes Tier 2 safety checks."
            
    elif tier >= 3:
        result = f"[APPROVED] Action '{action}' safely executed against Tier {tier} entity ({infra['asset_name']}). Zero critical blast radius."
        
    logger.info(f"Blast Radius Simulation Result: {result}")
    return result

@tool
def execute_firewall_change(action: str, target: str) -> str:
    """Production Execution: Commits the approved action to the network fabric."""
    logger.info(f"Tool Execution: execute_firewall_change(action={action}, target={target})")
    return f"[SUCCESS] Applied {action} to {target}. Network fabric routing updated successfully."

@tool
def verify_network_traffic(target: str) -> str:
    """Production Execution: Verifies if malicious outbound beaconing or exploitation has ceased."""
    logger.info(f"Tool Execution: verify_network_traffic(target={target})")
    return f"[VERIFIED] No further malicious egress or lateral movement traffic observed on {target}. Connections reset."

# Standard toolset exposed to the Investigator agent
soc_tools = [check_vulnerability, check_server_logs]