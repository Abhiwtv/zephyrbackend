from app.core.state import IncidentState

def intake_node(state: IncidentState) -> dict:
    """
    STATE 1: INTAKE
    Takes the NIDS context initialized by the API and formally 
    sets up the investigation whiteboard.
    """
    return {
        "status": "INTAKE",
        "hypotheses": [
            "H1: Successful exploitation",
            "H2: Failed exploitation",
            "H3: False positive"
        ],
        "missing_evidence": [
            f"Vulnerability status of target {state.target_ip}",
            f"Server logs for target {state.target_ip} confirming payload execution"
        ]
    }