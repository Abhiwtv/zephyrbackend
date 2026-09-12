import logging
from typing import Dict, Any
from langchain_core.messages import AIMessage
from app.core.state import IncidentState

logger = logging.getLogger("Zephyr-Intake")
logger.setLevel(logging.INFO)

def intake_node(state: IncidentState) -> Dict[str, Any]:
    """
    Deterministic triage node. Normalizes the alert and prepares the initial
    investigative canvas without expending LLM tokens.
    """
    logger.info(f"[{state.incident_id}] === INTAKE PHASE INITIATED ===")
    logger.info(f"[{state.incident_id}] Parsing alert: {state.alert_signature} from {state.source_ip} -> {state.target_ip}")
    
    # Establish baseline hypotheses based on the alert signature
    initial_hypotheses = [
        "H1 (Critical): The exploit payload executed successfully, granting the attacker initial access.",
        "H2 (Moderate): The payload was blocked by local host defenses or the application is patched.",
        "H3 (Low): This is a false positive triggered by an automated benign scanner."
    ]
    
    # Define the immediate forensic gaps
    missing_evidence = [
        f"Vulnerability status of target host {state.target_ip}",
        f"Server access logs and process execution logs for {state.target_ip}"
    ]
    
    logger.debug(f"[{state.incident_id}] Established hypotheses: {initial_hypotheses}")
    logger.debug(f"[{state.incident_id}] Identified evidence gaps: {missing_evidence}")
    
    return {
        "status": "INTAKE",
        "hypotheses": initial_hypotheses,
        "missing_evidence": missing_evidence,
        "messages": [AIMessage(content=f"Intake complete. Alert {state.alert_signature} normalized. Awaiting investigation.")]
    }