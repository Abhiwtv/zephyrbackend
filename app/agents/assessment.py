from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.core.llm import local_llm
import json

def assessment_node(state: IncidentState) -> dict:
    # Extract just the tool responses from the message history
    tool_messages = [msg.content for msg in state.messages if msg.type == "tool"]
    evidence_text = "\n".join(tool_messages)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the SOC Incident Assessment Agent. 
        Review the evidence and determine the outcome. 
        Output ONLY the requested raw JSON data structure. Do not include conversational filler, pleasantries, explanations, or apologies. Do not wrap the output in markdown blocks.
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
        # Clean the response in case the LLM wraps it in markdown blocks
        if isinstance(response.content, list):
            content_str = response.content[0].get("text", "") if isinstance(response.content[0], dict) else str(response.content[0])
        else:
            content_str = str(response.content)
        clean_json = content_str.replace("```json", "").replace("```", "").strip()
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