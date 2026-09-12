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
    # 1. Scan the message history for any Reviewer Rejections
    rejection_messages = [
        msg.content for msg in state.messages 
        if "Reviewer REJECT" in msg.content
    ]
    
    # 2. If no rejections happened, RART idles
    if not rejection_messages:
        return {
            "status": "COMPLETED",
            "messages": [AIMessage(content="RART Learned Strategy: No critical mistakes made. Standard operational flow maintained.")]
        }

    # 3. If there was a rejection, extract a rule based on the first rejection
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the RART Learning Engine. Your job is to extract strict operational policies from SOC mistakes.
        Look specifically at the Reviewer's REJECTION feedback. 
        Create ONE strict, permanent rule that prevents the Defense Generator from making this exact mistake again.
        Example: 'Never use BLOCK_SOURCE on 10.0.4.x NAT gateways; always use TARGETED_RULE.'"""),
        ("user", "Reviewer Rejection Reason: {rejection}\nFinal Approved Action: {action}")
    ])
    
    chain = prompt | local_llm.with_structured_output(LearnedStrategy)
    
    strategy = chain.invoke({
        "rejection": rejection_messages[0], # Feed it the exact rejection from history
        "action": state.proposed_action
    })
    
    learned_policy_db.append(strategy.policy)
    
    return {
        "status": "COMPLETED",
        "messages": [AIMessage(content=f"RART Learned Strategy: {strategy.policy}")]
    }