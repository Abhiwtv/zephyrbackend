import os
import logging
from supabase.client import create_client, Client
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_huggingface import HuggingFaceEmbeddings
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DB-Seeder")

load_dotenv()

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
if not supabase_url or not supabase_key:
    raise ValueError("Missing Supabase credentials in .env file.")

supabase: Client = create_client(supabase_url, supabase_key)
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# Curated Textbook Baseline Playbooks (Phase 1 RAG Only)
PLAYBOOKS = [
    {
        "category": "Inbound RCE",
        "signature": "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)",
        "textbook_sop": "STANDARD SOP: Block the offending source IP at the edge firewall immediately to halt the RCE attempt."
    },
    {
        "category": "SQL Injection",
        "signature": "ET WEB_SPECIFIC UNION SELECT SQLi Attempt",
        "textbook_sop": "STANDARD SOP: Null-route the internal backend server exhibiting the vulnerability to prevent data exfiltration."
    },
    {
        "category": "Lateral Movement / PtH",
        "signature": "ET POLICY SMBv2 NTLM SSP Authentication - Possible PtH",
        "textbook_sop": "STANDARD SOP: Terminate the VPN session and disable the associated Active Directory account immediately."
    },
    {
        "category": "C2 Beaconing",
        "signature": "ET MALWARE Cobalt Strike Beacon Observed",
        "textbook_sop": "STANDARD SOP: Block the destination IP or domain at the enterprise egress proxy."
    },
    {
        "category": "Kerberoasting",
        "signature": "ET POLICY Suspicious Kerberos TGS Request - RC4 Enctype",
        "textbook_sop": "STANDARD SOP: Reset the targeted SPN service account password immediately to break the offline cracking attempt."
    },
    {
        "category": "Ransomware",
        "signature": "ET TROJAN Ransomware File Extension Modification (.lockbit)",
        "textbook_sop": "STANDARD SOP: Instantly disable the file server's network adapter to halt encryption across the network share."
    },
    {
        "category": "DNS Tunneling",
        "signature": "ET POLICY Suspicious DNS TXT Record Request - High Entropy/Length",
        "textbook_sop": "STANDARD SOP: Block the corporate DNS resolver from forwarding traffic to external internet DNS servers."
    },
    {
        "category": "Password Spray",
        "signature": "ET SCAN Distributed Password Spray / Brute Force Attempt (Okta/SSO)",
        "textbook_sop": "STANDARD SOP: Lock out the user accounts experiencing repeated authentication failures."
    },
    {
        "category": "Living-off-the-Land",
        "signature": "ET MALWARE Suspicious PowerShell Base64 Encoded Command Line",
        "textbook_sop": "STANDARD SOP: Kill the PowerShell process and quarantine the host instance from the network."
    },
    {
        "category": "Benign Scanner",
        "signature": "ET SCAN Rapid Port Sweep / Nmap Aggressive",
        "textbook_sop": "STANDARD SOP: Add the source IP to the firewall blocklist to halt the scanning activity."
    }
]

def seed_playbooks():
    logger.info("Starting Database Seeding Process...")
    logger.info("Clearing old baseline playbooks...")
    
    # Target only the playbooks table to prevent overwriting your custom logs
    supabase.table("soc_playbooks").delete().neq("id", 0).execute()

    logger.info(f"Embedding {len(PLAYBOOKS)} Textbook SOPs into soc_playbooks...")
    playbook_texts = [s["textbook_sop"] for s in PLAYBOOKS]
    playbook_metadatas = [{"category": s["category"], "signature": s["signature"]} for s in PLAYBOOKS]
    
    SupabaseVectorStore.from_texts(
        texts=playbook_texts,
        metadatas=playbook_metadatas,
        embedding=embeddings,
        client=supabase,
        table_name="soc_playbooks",
        query_name="match_soc_playbooks"
    )

    logger.info("Database Seeding Complete! Playbooks are primed.")

if __name__ == "__main__":
    seed_playbooks()