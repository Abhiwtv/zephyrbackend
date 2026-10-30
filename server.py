import logging
import requests
import json
import subprocess
import shlex  # <--- CRITICAL for parsing LLM iptables commands safely
from typing import Dict, Any, Optional, Literal
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from openai import OpenAI

# Import your existing local project modules
from app.core.state import MitigationEnvelope
from app.agents.defense import RESPONDER_SYSTEM_PROMPT, build_responder_user_prompt

# --- SETUP LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Zephyr HITL Controller")

TUNNEL_URL = "https://appropriations-consumer-mon-farms.trycloudflare.com/v1"

# In-memory store for Human-In-The-Loop pending reviews
pending_mitigations: Dict[str, Dict[str, Any]] = {}

class ReviewDecision(BaseModel):
    approved: bool
    modified_iptables_cmd: Optional[str] = None

def remove_patterns_from_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Strips 'pattern' constraints that break llama.cpp's remote GBNF compiler."""
    if isinstance(schema, dict):
        return {k: remove_patterns_from_schema(v) for k, v in schema.items() if k != "pattern"}
    elif isinstance(schema, list):
        return [remove_patterns_from_schema(i) for i in schema]
    return schema

@app.post("/api/v1/alert")
async def process_alert(alert: Dict[str, Any]):
    """Receives raw alert, compresses PCAP data, and queries Kaggle LLM."""
    logger.info("==== NEW ALERT RECEIVED ====")
    
    alert_id = str(alert.get("alert_id", "unknown_alert"))
    
    # 1. Compress the payload using our builder before sending to Kaggle
    compressed_prompt = build_responder_user_prompt(alert)
    logger.info(f"Compressed Prompt Length: {len(compressed_prompt)} characters")
    
    raw_schema = MitigationEnvelope.model_json_schema()
    safe_schema = remove_patterns_from_schema(raw_schema)
    
    try:
        payload = {
            "model": "zephyr-dpo-v3",
            "messages": [
                {"role": "system", "content": RESPONDER_SYSTEM_PROMPT},
                {"role": "user", "content": compressed_prompt} # <-- Using the aggregated prompt here
            ],
            "temperature": 0.1,
            "max_tokens": 1024,
            "response_format": {
                "type": "json_object"
            }
        }
        
        logger.info(f"Routing to Kaggle Tunnel: {TUNNEL_URL}")
        
        response = requests.post(
            f"{TUNNEL_URL}/chat/completions", 
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        
        logger.info("Successfully received LLM generation from Kaggle.")
        
        response_data = response.json()
        raw_output = response_data["choices"][0]["message"]["content"]
        mitigation_envelope = json.loads(raw_output)
        
        logger.info(f"Locking mitigation in memory for alert: {alert_id}")
        pending_mitigations[alert_id] = mitigation_envelope
        
        return {
            "status": "pending_human_review",
            "alert_id": alert_id,
            "mitigation_envelope": mitigation_envelope
        }
        
    except Exception as e:
        logger.error(f"Pipeline Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/api/v1/execute/{alert_id}")
async def execute_mitigation(alert_id: str, decision: ReviewDecision):
    """Executes approved iptables commands safely inside the Docker network."""
    if alert_id not in pending_mitigations:
        raise HTTPException(status_code=404, detail="Alert not found or already executed.")
        
    envelope = pending_mitigations.pop(alert_id)
    
    if not decision.approved:
        return {"status": "rejected_by_operator", "alert_id": alert_id}
        
    action = envelope.get("chosen_mitigation", {})
    
    # RESILIENCE FIX: If the LLM drops the key, fallback to the known victim container
    target_container = action.get("target_container", "pc-4") 
    
    cmd_to_run = decision.modified_iptables_cmd or action.get("iptables_cmd")
    
    if cmd_to_run and target_container and action.get("action_type") != "NO_OP":
        if not cmd_to_run.strip().startswith("iptables"):
            raise HTTPException(status_code=400, detail="Invalid command: Must start with 'iptables'")

        safe_cmd_array = shlex.split(cmd_to_run)
        docker_cmd = ["docker", "exec", target_container] + safe_cmd_array
        
        logger.info(f"Executing Mitigation: {' '.join(docker_cmd)}")
        exec_result = subprocess.run(docker_cmd, capture_output=True, text=True)
        
        if exec_result.returncode != 0:
            logger.error(f"Docker Exec Failed: {exec_result.stderr}")
            raise HTTPException(status_code=500, detail=f"Docker Exec Failed: {exec_result.stderr}")
            
        return {"status": "executed", "target": target_container, "injected_cmd": cmd_to_run}
        
    return {"status": "no_action_required_or_no_op", "target": target_container}

class AttackSimulation(BaseModel):
    attacker_node: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    target_ip: str
    target_port: int
    packet_count: int = 10000

@app.post("/api/v1/simulate_attack")
async def simulate_attack(sim: AttackSimulation):
    """Dynamically installs hping3 and blasts a SYN flood across the Docker bridge."""
    try:
        attack_cmd = (
            f"apk add --no-cache hping3 --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing && "
            f"hping3 -c {sim.packet_count} -i u100 -S -p {sim.target_port} {sim.target_ip}"
        )
        
        subprocess.Popen(
            ["docker", "exec", sim.attacker_node, "sh", "-c", attack_cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        return {
            "status": "attack_launched",
            "attacker": sim.attacker_node,
            "target": sim.target_ip,
            "command": attack_cmd
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))