import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.core.llm import creative_llm
from app.core.rag import save_learned_policy, write_learning_ledger

logger = logging.getLogger("Zephyr-RART")
logger.setLevel(logging.INFO)

class PolicyPatch(BaseModel):
    """Strict schema forcing the LLM to abstract the failure rather than overfit to a single IP."""
    target_class: str = Field(description="Broad category of the infrastructure (e.g., CDN_EDGE, INTERNAL_GATEWAY, ISP_NODE).")
    disallowed_action: str = Field(description="The specific action that was rejected by the reviewer.")
    mandated_alternative: str = Field(description="A safe, viable alternative mitigation (e.g., ISOLATE_ASSET).")
    abstract_rule: str = Field(description="A single, generalized sentence overriding the standard playbook for this infrastructure class.")

def rart_node(state: IncidentState) -> Dict[str, Any]:
    """
    The Evolution Node.
    Abstracts a near-miss into a permanent episodic memory constraint and writes it to the database.
    """
    logger.info(f"[{state.incident_id}] === RART POLICY MUTATION INITIATED ===")
    logger.warning(f"[{state.incident_id}] Processing Near-Miss: {state.proposed_action} on {state.proposed_target}")
    logger.warning(f"[{state.incident_id}] Simulated Blast Radius: {state.simulated_blast_radius}")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the RART (Red Team AI Reporting Tool) Engine.
        A proposed SOC mitigation just triggered a catastrophic near-miss in the simulation environment.
        Your job is to abstract this specific failure into a generalized security policy constraint.
        Do NOT write a rule for the specific IP. Write a rule for the CLASS of infrastructure that IP belongs to.
        Output MUST match the strict JSON schema provided."""),
        ("user", """
        Failed Action Attempted: {action}
        Target IP: {target}
        Simulated Environmental Impact: {impact}
        """)
    ])
    
    try:
        # We use the 'creative_llm' (temp=0.6) here to encourage better abstraction and generalization
        structured_llm = creative_llm.with_structured_output(PolicyPatch)
        chain = prompt | structured_llm
        
        patch: PolicyPatch = chain.invoke({
            "action": state.proposed_action, 
            "target": state.proposed_target, 
            "impact": state.simulated_blast_radius
        })
        
        logger.info(f"[{state.incident_id}] RART Synthesized Rule: {patch.abstract_rule}")
        logger.debug(f"[{state.incident_id}] RART Abstraction: {patch.disallowed_action} -> {patch.mandated_alternative} for {patch.target_class}")
        
        # 1. Embed to Vector DB (Episodic Memory for future Phase 2 Retrieval)
        save_learned_policy(
            incident_id=state.incident_id, 
            rule=patch.abstract_rule, 
            target_class=patch.target_class
        )
        
        # 2. Write to Relational DB (The Hackathon Dashboard Audit Trail)
        write_learning_ledger(
            incident_id=state.incident_id, 
            failed_action=f"{state.proposed_action} on {state.proposed_target}", 
            blast_radius=state.simulated_blast_radius, 
            rule=patch.abstract_rule
        )
        
        return {
            "status": "ADAPTING",
            "learned_rule": patch.abstract_rule,
            "messages": [AIMessage(content=f"RART Policy Mutated: {patch.abstract_rule}. Routing back to Defense...")]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] RART Synthesis Failure: {str(e)}")
        fallback_rule = f"Never use {state.proposed_action} on targets similar to {state.proposed_target}."
        return {
            "status": "ADAPTING",
            "learned_rule": fallback_rule,
            "messages": [AIMessage(content=f"RART Fallback Mutated: {fallback_rule}")]
        }