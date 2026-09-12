from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field
from typing import Literal
from app.core.state import IncidentState
from app.core.llm import local_llm

class ReviewDecision(BaseModel):
    decision: Literal["APPROVE", "REJECT"] = Field(description="APPROVE if safe, REJECT if unsafe or disproportionate.")
    feedback: str = Field(description="Explanation of the decision or required changes if rejected.")

def reviewer_node(state: IncidentState) -> dict:
    """
    STATE 8: REVIEWING
    Evaluates the proposed defense against organizational constraints.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the SOC Response Reviewer. Evaluate the proposed action. 
        CRITICAL ORGANIZATIONAL CONSTRAINT: The 10.0.4.0/24 subnet is a shared internal NAT gateway. 
        Blocking any IP in this range will cause massive collateral damage. 
        If the proposed action is BLOCK_SOURCE on a 10.0.4.x IP, you MUST REJECT it and demand a TARGETED_RULE (like an application-level WAF block)."""),
        ("user", "Proposed Action: {action}\nTarget: {target}\nJustification: {justification}")
    ])
    
    chain = prompt | local_llm.with_structured_output(ReviewDecision)
    
    review = chain.invoke({
        "action": state.proposed_action,
        "target": state.proposed_target,
        "justification": state.action_justification
    })
    
    return {
        "status": "REVIEWING",
        "reviewer_decision": review.decision,
        "reviewer_feedback": review.feedback,
        "messages": [AIMessage(content=f"Reviewer {review.decision}: {review.feedback}")]
    }