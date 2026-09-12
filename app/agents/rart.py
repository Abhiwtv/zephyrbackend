from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field
from app.core.state import IncidentState
from app.core.llm import local_llm
from app.core.memory_store import learned_policy_db

class LearnedStrategy(BaseModel):
    policy: str = Field(description="A single, generalized sentence instructing the SOC how to handle similar situations in the future.")

def rart_node(state: IncidentState) -> dict:
    """
    STATE 13: RART LEARNING LOOP
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the RART Learning Engine. Your job is to extract strict operational policies from SOC mistakes.
        Look specifically at the Reviewer's REJECTION feedback. 
        Create ONE strict, permanent rule that prevents the Defense Generator from making this exact mistake again.
        Example: 'Never use BLOCK_SOURCE on 10.0.4.x NAT gateways; always use TARGETED_RULE.'"""),
        ("user", "Reviewer Rejection Reason: {rejection}\nFinal Approved Action: {action}")
    ])
    
    chain = prompt | local_llm.with_structured_output(LearnedStrategy)
    
    # Only run RART extraction if there was actually a rejection to learn from
    if state.reviewer_decision == "APPROVE" and not state.reviewer_feedback.startswith("The proposed action of BLOCK_SOURCE"):
        policy_text = "No critical mistakes made. Standard operational flow maintained."
    else:
        strategy = chain.invoke({
            "rejection": state.reviewer_feedback,
            "action": state.proposed_action
        })
        policy_text = strategy.policy
        learned_policy_db.append(policy_text)
    
    return {
        "status": "COMPLETED",
        "messages": [AIMessage(content=f"RART Learned Strategy: {policy_text}")]
    }