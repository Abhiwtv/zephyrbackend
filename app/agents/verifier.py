import logging
from typing import Dict, Any
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.tools.mock_env import verify_network_traffic

logger = logging.getLogger("Zephyr-Verifier")
logger.setLevel(logging.INFO)

def verifier_node(state: IncidentState) -> Dict[str, Any]:
    """
    Post-execution validation. Checks if the mitigation actually stopped the threat activity.
    """
    logger.info(f"[{state.incident_id}] === VERIFICATION PHASE INITIATED ===")
    
    try:
        result = verify_network_traffic.invoke({"target": state.proposed_target})
        logger.info(f"[{state.incident_id}] Verification Output: {result}")
        
        return {
            "status": "VERIFYING",
            "verification_result": result,
            "messages": [AIMessage(content=f"Verifier: {result}")]
        }
    except Exception as e:
        logger.error(f"[{state.incident_id}] Verification Failure: {str(e)}")
        return {
            "status": "VERIFYING",
            "verification_result": "UNABLE TO VERIFY TRAFFIC",
            "messages": [AIMessage(content="Verifier: Telemetry unavailable.")]
        }