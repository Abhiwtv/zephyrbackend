from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.core.llm import local_llm
import json

def assessment_node(state: IncidentState) -> dict:
    """
    STATE 6: ASSESSING
    The LLM reviews the gathered evidence and makes a final determination on the attack outcome.
    """
    # Extract just the tool responses from the message history
    tool_messages = [msg.content for msg in state.messages if msg.type == "tool"]
    evidence_text = "\n".join(tool_messages)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the SOC Incident Assessment Agent. 
        Review the evidence and determine the outcome. 
        You must output ONLY a valid JSON object with the following schema, and no other text:
        {{
            "outcome": "ATTACK_SUCCEEDED" | "ATTACK_FAILED" | "FALSE_POSITIVE",
            "confidence": float (0.0 to 1.0),
            "reasoning": "brief explanation"
        }}"""),
        ("user", "Alert: {signature}\nEvidence Gathered:\n{evidence}")
    ])
    
    chain = prompt | local_llm
    
    response = chain.invoke({
        "signature": state.alert_signature,
        "evidence": evidence_text
    })
    
    # Parse the JSON response
    try:
        # Clean the response in case the local LLM wraps it in markdown blocks
        clean_json = response.content.replace("```json", "").replace("```", "").strip()
        assessment_data = json.loads(clean_json)
    except json.JSONDecodeError:
        # Fallback if the local model fails strict JSON formatting
        assessment_data = {
            "outcome": "UNKNOWN",
            "confidence": 0.0,
            "reasoning": f"Failed to parse LLM output: {response.content}"
        }

    # Replace the return statement in assessment_node with this:
    return {
        "status": "ASSESSING", # Transitioning into assessing
        "confidence": assessment_data.get("confidence", 0.0),
        "assessment_outcome": assessment_data.get("outcome", "UNKNOWN"),
        "assessment_justification": assessment_data.get("reasoning", ""),
        "messages": [AIMessage(content=f"Assessment: {assessment_data.get('outcome')} - {assessment_data.get('reasoning')}")]
    }