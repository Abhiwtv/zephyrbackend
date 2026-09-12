import pytest
from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

def test_full_graph_execution_cycle():
    """
    Executes an end-to-end incident through the compiled LangGraph state machine.
    Verifies that the alert progresses from intake down to judge scorecard output.
    """
    initial_state = IncidentState(
        incident_id="INC-UNIT-TEST",
        alert_signature="ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)",
        source_ip="104.28.15.12",
        target_ip="10.0.1.15"
    )

    # Synchronous invocation through LangGraph
    final_output = soc_graph.invoke(initial_state)
    state = final_output if isinstance(final_output, dict) else final_output.model_dump()

    # Core validation checks
    assert state["status"] == "COMPLETED", f"Pipeline terminated abnormally at: {state['status']}"
    assert state["incident_id"] == "INC-UNIT-TEST"
    assert state["reviewer_decision"] in ["APPROVE", "REJECT"]
    assert state["execution_result"] != ""
    assert state["verification_result"] != ""
    
    # Ensure scorecard generation produced valid criteria
    scorecard = state.get("judge_scorecard", {})
    assert isinstance(scorecard, dict)
    assert "containment_score" in scorecard
    assert "blast_radius_score" in scorecard
    assert "final_verdict" in scorecard

def test_graph_reviewer_gate_resolution():
    """
    Verifies that an alert against a protected CDN either triggers an
    adaptive RART mutation or is safely contained without network degradation.
    """
    initial_state = IncidentState(
        incident_id="INC-GATE-CHECK",
        alert_signature="ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)",
        source_ip="104.28.15.12",
        target_ip="10.0.1.15"
    )

    final_output = soc_graph.invoke(initial_state)
    state = final_output if isinstance(final_output, dict) else final_output.model_dump()

    # If the initial proposal was a fatal drop, a learned rule must have been synthesized
    if "[FATAL]" in state.get("simulated_blast_radius", ""):
        assert state.get("learned_rule") is not None
        assert len(state.get("learned_rule", "")) > 0

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main(["-v", "-s", __file__]))