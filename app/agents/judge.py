from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field
from app.core.state import IncidentState
from app.core.llm import local_llm

class JudgeScorecard(BaseModel):
    investigation_score: int = Field(description="Score 1-10 on hypothesis formation and tool selection.")
    evidence_score: int = Field(description="Score 1-10 on interpreting the tool results correctly.")
    decision_score: int = Field(description="Score 1-10 on the accuracy of the final assessment.")
    response_score: int = Field(description="Score 1-10 on the safety and effectiveness of the final mitigation.")
    adaptation_score: int = Field(description="Score 1-10 on how well the agent recovered from the reviewer's rejection.")
    critical_feedback: str = Field(description="One sentence summarizing the biggest mistake or best adaptation.")

def judge_node(state: IncidentState) -> dict:
    """
    STATE 12: POSTMORTEM
    Evaluates the completed incident and generates an organizational scorecard.
    """
    # Compile the incident timeline for the judge
    timeline = f"""
    Alert: {state.alert_signature}
    Missing Evidence Searched: {state.missing_evidence}
    Initial Proposed Action: BLOCK_SOURCE (Rejected by Reviewer)
    Adapted Action: {state.proposed_action} (Approved)
    Final Outcome: {state.assessment_outcome}
    Verification: {state.verification_result}
    """
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the SOC Judge Orchestrator. Evaluate the AI agent's performance on this incident. 
        Pay special attention to how it adapted its response after the initial rejection.
        Provide strict 1-10 scores and a brief feedback summary."""),
        ("user", "Incident Timeline:\n{timeline}")
    ])
    
    chain = prompt | local_llm.with_structured_output(JudgeScorecard)
    
    scorecard = chain.invoke({"timeline": timeline})
    
    # Convert Pydantic model to dict for state storage
    scorecard_dict = scorecard.model_dump()
    
    return {
        "status": "COMPLETED",
        "judge_scorecard": scorecard_dict,
        "messages": [AIMessage(content=f"Judge Scorecard Generated: {scorecard.critical_feedback}")]
    }