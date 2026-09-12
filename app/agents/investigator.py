import logging
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.core.llm import local_llm

logger = logging.getLogger("Zephyr-Investigator")
logger.setLevel(logging.INFO)

def investigator_node(state: IncidentState) -> Dict[str, Any]:
    """
    LLM-driven investigative node. Analyzes the hypotheses and explicitly defines
    the forensic queries required for the Strategist to execute.
    """
    logger.info(f"[{state.incident_id}] === INVESTIGATION PHASE INITIATED ===")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a Tier 3 SOC Investigator.
        Review the inbound alert and the current hypotheses. 
        Your ONLY job is to explicitly state what telemetry or evidence is missing to prove if the attack succeeded.
        Be extremely concise and technical. Do not propose mitigations."""),
        ("user", """Alert Signature: {signature}
        Source IP: {source}
        Target IP: {target}
        Current Hypotheses: {hypotheses}
        Initial Missing Evidence: {missing}""")
    ])
    
    logger.debug(f"[{state.incident_id}] Invoking local LLM for evidence refinement...")
    
    try:
        chain = prompt | local_llm
        response = chain.invoke({
            "signature": state.alert_signature, 
            "source": state.source_ip, 
            "target": state.target_ip, 
            "hypotheses": " | ".join(state.hypotheses),
            "missing": " | ".join(state.missing_evidence)
        })
        
        logger.info(f"[{state.incident_id}] Investigator Output: {response.content.strip()}")
        
        return {
            "status": "INVESTIGATING",
            "messages": [AIMessage(content=f"Investigator Requirement: {response.content}")]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] Investigator LLM failure: {str(e)}")
        return {
            "status": "INVESTIGATING",
            "messages": [AIMessage(content="Investigator Requirement: SYSTEM FAILURE. Proceed with default evidence gathering.")]
        }