import logging
from typing import Dict, Any
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.tools.mock_env import simulate_blast_radius

logger = logging.getLogger("Zephyr-Reviewer")
logger.setLevel(logging.INFO)

def reviewer_node(state: IncidentState) -> Dict[str, Any]:
    """
    The Near-Miss Simulation Gate.
    Calculates the exact infrastructure impact of the proposed defense plan before it executes.
    Routes to EXECUTION if safe, or RART if catastrophic.
    """
    logger.info(f"[{state.incident_id}] === REVIEWER & MCTS SIMULATION PHASE INITIATED ===")
    logger.info(f"[{state.incident_id}] Simulating action: {state.proposed_action} on {state.proposed_target}")
    
    try:
        # Organically invoke the blast radius simulator (mocking a BGP/ASN lookup)
        simulated_impact = simulate_blast_radius.invoke({
            "action": state.proposed_action, 
            "target": state.proposed_target
        })
        
        logger.info(f"[{state.incident_id}] Blast Radius Result: {simulated_impact}")
        
        # Heuristic Evaluation
        if "[FATAL]" in simulated_impact:
            decision = "REJECT"
            feedback = f"Simulation Blocked: Action triggers unacceptable collateral damage. {simulated_impact}"
            logger.warning(f"[{state.incident_id}] REVIEWER REJECTED PLAN. Routing to RART adaptation loop.")
        else:
            decision = "APPROVE"
            feedback = f"Simulation Passed: Action safe for production execution. {simulated_impact}"
            logger.info(f"[{state.incident_id}] REVIEWER APPROVED PLAN. Routing to Executor.")
            
        return {
            "status": "REVIEWING",
            "simulated_blast_radius": simulated_impact,
            "reviewer_decision": decision,
            "reviewer_feedback": feedback,
            "messages": [AIMessage(content=f"Reviewer {decision}: {feedback}")]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] Reviewer Simulation Failure: {str(e)}")
        # If the simulator crashes, fail secure (Reject)
        return {
            "status": "REVIEWING",
            "simulated_blast_radius": "SIMULATOR_CRASH",
            "reviewer_decision": "REJECT",
            "reviewer_feedback": "Reviewer subsystem failure. Plan rejected as a safety precaution.",
            "messages": [AIMessage(content="Reviewer REJECT: Simulator crash. Fail secure activated.")]
        }