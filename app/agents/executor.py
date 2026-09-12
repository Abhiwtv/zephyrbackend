from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.tools.mock_env import simulate_firewall

def executor_node(state: IncidentState) -> dict:
    """
    STATE 9: EXECUTING
    Deterministically executes the approved action in the sandbox.
    """
    if state.proposed_action in ["NO_ACTION", "MONITOR"]:
        result = f"[SUCCESS] Action {state.proposed_action} on {state.proposed_target} logged cleanly (no firewall change)."
    else:
        # Call the sandbox tool directly
        result = simulate_firewall.invoke({
            "action": state.proposed_action, 
            "target": state.proposed_target
        })
    
    return {
        "status": "EXECUTING",
        "execution_result": result,
        "messages": [AIMessage(content=f"Executor: {result}")]
    }