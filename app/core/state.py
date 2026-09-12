from typing import List, Annotated, Sequence, Literal
from pydantic import BaseModel, Field
import operator
from langchain_core.messages import BaseMessage

class IncidentState(BaseModel):
    incident_id: str
    status: Literal[
        "ALERT_RECEIVED", 
        "INTAKE", 
        "INVESTIGATING", 
        "EVIDENCE_PLANNING",
        "ASSESSING",
        "DEFENDING",
        "REVIEWING",
        "EXECUTING",
        "VERIFYING",
        "ADAPTING",
        "COMPLETED"
    ] = "ALERT_RECEIVED"
    
    # Context
    alert_signature: str = ""
    source_ip: str = ""
    target_ip: str = ""
    
    # Investigation State
    hypotheses: List[str] = Field(default_factory=list)
    evidence_gathered: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    
    # LangGraph message history (reducer pattern for appending)
    messages: Annotated[Sequence[BaseMessage], operator.add] = Field(default_factory=list)
    
    # Assessment State
    assessment_outcome: str = ""
    assessment_justification: str = ""
    
    # Response State
    proposed_action: str = ""
    proposed_target: str = ""
    action_justification: str = ""
    
    # Review State
    reviewer_decision: Literal["APPROVE", "REJECT", "PENDING"] = "PENDING"
    reviewer_feedback: str = ""
    
    # Execution & Verification
    execution_result: str = ""
    verification_result: str = ""
    
    # Organizational Memory & Evaluation
    judge_scorecard: dict = Field(default_factory=dict)