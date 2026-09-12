import operator
from typing import List, Annotated, Sequence, Literal, Dict, Any
from pydantic import BaseModel, Field
from langchain_core.messages import BaseMessage

class IncidentState(BaseModel):
    """
    The unified state object that is passed between all LangGraph nodes.
    Acts as the complete contextual memory for a single attack simulation.
    """
    # --- Core Identifiers ---
    incident_id: str = Field(description="Unique tracking ID for the alert")
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
        "COMPLETED",
        "FAILED"
    ] = Field(default="ALERT_RECEIVED", description="Current node phase")
    
    # --- Alert Context ---
    alert_signature: str = Field(default="", description="e.g., CVE-2021-44228 JNDI RCE")
    source_ip: str = Field(default="", description="Attacker IP")
    target_ip: str = Field(default="", description="Victim IP or internal asset")
    
    # --- Investigator & Strategist Artifacts ---
    hypotheses: List[str] = Field(default_factory=list, description="Theories about the attack success")
    evidence_gathered: List[str] = Field(default_factory=list, description="Raw logs or tool outputs")
    missing_evidence: List[str] = Field(default_factory=list, description="Forensic gaps identified")
    
    # --- Assessor Artifacts ---
    assessment_outcome: str = Field(default="", description="ATTACK_SUCCEEDED or ATTACK_FAILED")
    confidence: float = Field(default=0.0, description="Mathematical certainty of the assessment")
    assessment_justification: str = Field(default="", description="Reasoning for the outcome")
    
    # --- Two-Phase Retrieval (RAG) Memory ---
    textbook_playbook: str = Field(default="", description="Phase 1: Baseline textbook SOC SOP")
    historical_context: str = Field(default="", description="Phase 2: RART-generated past mistakes (Overrides Phase 1)")
    
    # --- Defense Node Proposals ---
    proposed_action: str = Field(default="", description="The exact mitigation (e.g., BLOCK_SOURCE, ISOLATE_ASSET)")
    proposed_target: str = Field(default="", description="The infrastructure target of the action")
    action_justification: str = Field(default="", description="LLM reasoning for choosing this action")
    
    # --- Reviewer Simulation (The Guardrail) ---
    reviewer_decision: Literal["APPROVE", "REJECT", "PENDING"] = Field(default="PENDING")
    reviewer_feedback: str = Field(default="", description="Feedback passed back to Defense if rejected")
    simulated_blast_radius: str = Field(default="", description="Calculated infrastructure damage if executed")
    
    # --- RART (Policy Mutation) ---
    learned_rule: str = Field(default="", description="The compressed semantic rule generated from a near-miss")
    
    # --- Final Execution ---
    execution_result: str = Field(default="", description="Result from pushing the action to the network fabric")
    verification_result: str = Field(default="", description="Validation that traffic stabilized")
    judge_scorecard: Dict[str, Any] = Field(default_factory=dict, description="Hackathon evaluation metrics")

    # --- LangChain Message History ---
    # The Annotated operator.add ensures that returning new messages in a node APPENDS to this list
    # rather than overwriting it, preserving the full conversational graph.
    messages: Annotated[Sequence[BaseMessage], operator.add] = Field(default_factory=list)