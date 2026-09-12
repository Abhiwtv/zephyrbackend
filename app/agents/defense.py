from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field
from typing import Literal
from app.core.state import IncidentState
from app.core.llm import local_llm
from app.core.memory_store import learned_policy_db

class DefensePlan(BaseModel):
    action: Literal[
        "BLOCK_SOURCE", 
        "BLOCK_DESTINATION", 
        "TARGETED_RULE", 
        "ISOLATE_ASSET", 
        "MONITOR", 
        "GATHER_MORE_EVIDENCE", 
        "NO_ACTION"
    ] = Field(description="The exact response action to take.")
    # Update this specific line:
    target: str = Field(description="ONLY the raw IP address (e.g., '10.0.4.23'). Do not add labels or prefixes.")
    justification: str = Field(description="Why this action is proportional and justified.")

def defense_node(state: IncidentState) -> dict:
    active_policies = "\n".join([f"- {rule}" for rule in learned_policy_db]) if learned_policy_db else "None yet."
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the SOC Defense Generator. Based on the incident assessment, propose a response action. 
        Ensure the action is proportional.
        
        CRITICAL ORGANIZATIONAL POLICIES (LEARNED FROM PAST INCIDENTS):
        {policies}
        
        CRITICAL RULES:
        1. If you receive Previous Reviewer Feedback, you MUST propose a DIFFERENT action (e.g., TARGETED_RULE) that satisfies the constraints.
        2. The proposed_target MUST be a valid IP address. Never use descriptive text, attack names, or summaries.
        3. NEVER apply mitigation rules to the Target/Victim IP. Mitigation MUST be applied to the malicious Source IP."""),
        ("user", "Alert: {signature}\nSource IP: {source}\nTarget IP: {target}\nAssessment Outcome: {outcome}\nAssessment Justification: {justification}\n\nPrevious Reviewer Feedback: {feedback}")
    ])
    
    chain = prompt | local_llm.with_structured_output(DefensePlan)
    
    # 3. Execute exactly once
    plan = chain.invoke({
        "policies": active_policies,
        "signature": state.alert_signature,
        "source": state.source_ip,
        "target": state.target_ip,
        "outcome": state.assessment_outcome,
        "justification": state.assessment_justification,
        "feedback": state.reviewer_feedback if state.reviewer_decision == "REJECT" else "None."
    })
    
    return {
        "status": "DEFENDING",
        "proposed_action": plan.action,
        "proposed_target": plan.target,
        "action_justification": plan.justification,
        "messages": [AIMessage(content=f"Defense Proposed: {plan.action} on {plan.target}. Justification: {plan.justification}")]
    }