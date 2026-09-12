import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.core.llm import local_llm
from app.core.rag import get_playbook_retriever, get_postmortem_retriever

logger = logging.getLogger("Zephyr-Defense")
logger.setLevel(logging.INFO)

class DefensePlan(BaseModel):
    """
    Strict schema ensuring the LLM outputs actionable, deterministic mitigation commands.
    """
    action: str = Field(description="Exact response action (e.g., BLOCK_SOURCE, ISOLATE_ASSET, TARGETED_RULE).")
    target: str = Field(description="ONLY the raw target IP address or asset identifier.")
    justification: str = Field(description="Brief explanation of why this action is chosen, explicitly citing RAG context.")

def defense_node(state: IncidentState) -> Dict[str, Any]:
    """
    The Two-Phase Retrieval Node. 
    Constructs a defense plan by pitting baseline SOC playbooks against historical episodic memory.
    """
    logger.info(f"[{state.incident_id}] === DEFENSE PLANNING PHASE INITIATED ===")
    
    # --- PHASE 1: Baseline Textbook Retrieval ---
    logger.debug(f"[{state.incident_id}] Phase 1: Querying soc_playbooks...")
    try:
        playbook_retriever = get_playbook_retriever(k=1)
        playbook_docs = playbook_retriever.invoke(f"{state.alert_signature} {state.assessment_outcome}")
        playbook_context = playbook_docs[0].page_content if playbook_docs else "No standard playbook found. Proceed with general containment."
        logger.info(f"[{state.incident_id}] Baseline Playbook Loaded: {playbook_context[:60]}...")
    except Exception as e:
        logger.error(f"[{state.incident_id}] Phase 1 Retrieval Failed: {str(e)}")
        playbook_context = "SYSTEM ERROR: Playbook unavailable."

    # --- PHASE 2: Episodic Memory Retrieval ---
    logger.debug(f"[{state.incident_id}] Phase 2: Querying incident_postmortems for past mistakes...")
    try:
        history_retriever = get_postmortem_retriever(k=2)
        history_query = f"Mistakes handling {state.source_ip} or {state.target_ip} or {state.alert_signature}"
        history_docs = history_retriever.invoke(history_query)
        history_context = "\n".join([d.page_content for d in history_docs]) if history_docs else ""
        
        if history_context:
            logger.warning(f"[{state.incident_id}] CRITICAL: Historical overrides found! Injecting into prompt.")
        else:
            logger.info(f"[{state.incident_id}] No historical mistakes found for this vector.")
    except Exception as e:
        logger.error(f"[{state.incident_id}] Phase 2 Retrieval Failed: {str(e)}")
        history_context = ""

    # --- Synthesis & Prompt Resolution ---
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the Lead SOC Defense Architect.
        Formulate a mitigation plan based strictly on the provided intelligence.
        
        PHASE 1 (STANDARD PLAYBOOK):
        {playbook}
        
        PHASE 2 (PAST MISTAKES - CRITICAL OVERRIDE):
        {history}
        
        ABSOLUTE GOVERNING RULES:
        1. If PHASE 2 (PAST MISTAKES) contains a rule that contradicts PHASE 1, you MUST prioritize Phase 2. To ignore a past mistake is a critical failure.
        2. If you receive 'Previous Reviewer Feedback' rejecting your last plan, you MUST propose a DIFFERENT action to avoid an infinite loop.
        3. Never target a benign or unknown entity. Target the attacker or isolate the victim."""),
        ("user", """
        Source IP (Attacker): {source}
        Target IP (Victim): {target}
        Assessment Outcome: {outcome}
        Previous Reviewer Feedback: {feedback}
        """)
    ])
    
    # Inject feedback if this is a second-pass after a Reviewer rejection
    feedback_context = state.reviewer_feedback if state.reviewer_decision == "REJECT" else "None. First attempt."
    
    logger.debug(f"[{state.incident_id}] Invoking LLM with structured DefensePlan constraints...")
    
    try:
        # Enforce output via LangChain's native function calling Pydantic binder
        structured_llm = local_llm.with_structured_output(DefensePlan)
        chain = prompt | structured_llm
        
        plan: DefensePlan = chain.invoke({
            "playbook": playbook_context, 
            "history": history_context if history_context else "None.", 
            "source": state.source_ip, 
            "target": state.target_ip, 
            "outcome": state.assessment_outcome, 
            "feedback": feedback_context
        })
        
        logger.info(f"[{state.incident_id}] Defense Plan Formulated -> Action: {plan.action} | Target: {plan.target}")
        logger.info(f"[{state.incident_id}] Plan Justification: {plan.justification}")
        
        return {
            "status": "DEFENDING",
            "textbook_playbook": playbook_context,
            "historical_context": history_context,
            "proposed_action": plan.action,
            "proposed_target": plan.target,
            "action_justification": plan.justification,
            "messages": [AIMessage(content=f"Defense Strategy: Execute {plan.action} on {plan.target}. Justification: {plan.justification}")]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] Defense node failure: {str(e)}")
        # Safe fallback to prevent system crash
        return {
            "status": "DEFENDING",
            "proposed_action": "ISOLATE_ASSET",
            "proposed_target": state.target_ip,
            "action_justification": "Fallback strategy activated due to inference failure.",
            "messages": [AIMessage(content="Defense Strategy: SYSTEM FAILURE. Defaulting to victim isolation.")]
        }