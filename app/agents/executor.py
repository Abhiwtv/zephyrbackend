import logging
from typing import Dict, Any
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.tools.mock_env import execute_firewall_change

logger = logging.getLogger("Zephyr-Executor")
logger.setLevel(logging.INFO)

def executor_node(state: IncidentState) -> Dict[str, Any]:
    """
    Commits the approved defense plan to the network environment.
    """
    logger.info(f"[{state.incident_id}] === PRODUCTION EXECUTION INITIATED ===")
    logger.info(f"[{state.incident_id}] Executing: {state.proposed_action} on {state.proposed_target}")
    
    try:
        result = execute_firewall_change.invoke({
            "action": state.proposed_action, 
            "target": state.proposed_target
        })
        
        logger.info(f"[{state.incident_id}] Execution Output: {result}")
        
        return {
            "status": "EXECUTING",
            "execution_result": result,
            "messages": [AIMessage(content=f"Executor: {result}")]
        }
    except Exception as e:
        logger.error(f"[{state.incident_id}] Execution Failure: {str(e)}")
        return {
            "status": "EXECUTING",
            "execution_result": f"SYSTEM FAILURE: {str(e)}",
            "messages": [AIMessage(content=f"Executor System Failure: {str(e)}")]
        }