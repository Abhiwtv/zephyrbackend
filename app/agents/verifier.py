from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.tools.mock_env import verify_network_traffic

def verifier_node(state: IncidentState) -> dict:
    """
    STATE 10: VERIFYING
    Checks the sandbox environment to confirm the mitigation worked.
    """
    # Call the verification tool
    result = verify_network_traffic.invoke({"target": state.proposed_target})
    
    # In a fully expanded version, an LLM would evaluate this string to return a boolean.
    # For now, we update the state directly to COMPLETE.
    return {
        "status": "COMPLETED",
        "verification_result": result,
        "messages": [AIMessage(content=f"Verification: {result}")]
    }