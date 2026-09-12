from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.core.llm import local_llm

def investigator_node(state: IncidentState) -> dict:
    """
    STATE 2: INVESTIGATING
    The LLM analyzes the intake context and sets the investigation direction.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an autonomous SOC Investigator. Your job is to analyze the initial alert and state what missing evidence is required to prove if the attack succeeded. Be brief and output only the logical next steps."),
        ("user", "Alert: {signature}\nSource: {source}\nTarget: {target}\nCurrent Hypotheses: {hypotheses}")
    ])
    
    chain = prompt | local_llm
    
    response = chain.invoke({
        "signature": state.alert_signature,
        "source": state.source_ip,
        "target": state.target_ip,
        "hypotheses": ", ".join(state.hypotheses)
    })
    
    # Update state and append the LLM's reasoning to the message history
    return {
        "status": "INVESTIGATING",
        "messages": [AIMessage(content=f"Investigator Reasoning: {response.content}")]
    }