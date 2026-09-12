from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from app.core.state import IncidentState
from app.agents.intake import intake_node
from app.agents.investigator import investigator_node
from app.agents.strategist import strategist_node
from app.agents.assessment import assessment_node
from app.tools.mock_env import soc_tools
from app.core.llm import local_llm
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from app.agents.defense import defense_node
from app.agents.reviewer import reviewer_node
from app.agents.executor import executor_node
from app.agents.verifier import verifier_node
from app.agents.judge import judge_node
from app.agents.rart import rart_node


class SufficiencyCheck(BaseModel):
    is_sufficient: bool = Field(description="True if we have enough evidence to confidently assess if the attack succeeded or failed.")

def check_evidence_sufficiency(state: IncidentState) -> str:
    """
    STATE 5: STATE_UPDATE & ROUTING
    Checks the whiteboard to see if we need to loop back to the Strategist (State 3) 
    or proceed to Assessment (State 6).
    """
    # Extract tool observations
    tool_messages = [msg.content for msg in state.messages if msg.type == "tool"]
    evidence_text = "\n".join(tool_messages)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are the SOC Orchestrator. Review the gathered evidence. Do we have enough conclusive evidence to prove whether the SQL injection attack succeeded or failed? Answer purely based on the evidence."),
        ("user", "Missing Evidence goals: {missing}\n\nEvidence Gathered:\n{evidence}")
    ])
    
    # Force the LLM to output our structured JSON boolean
    chain = prompt | local_llm.with_structured_output(SufficiencyCheck)
    
    result = chain.invoke({
        "missing": ", ".join(state.missing_evidence),
        "evidence": evidence_text
    })
    
    if result.is_sufficient:
        print("➡️ Orchestrator: Evidence is sufficient. Moving to Assessment.")
        return "assessing"
    else:
        print("🔄 Orchestrator: Evidence insufficient. Looping back to Strategist.")
        return "strategist"

def route_review(state: IncidentState):
    if state.reviewer_decision == "APPROVE":
        print("✅ Reviewer APPROVED. Moving to Execution.")
        return "executing"  # Changed from END
    else:
        print("❌ Reviewer REJECTED. Looping back to Adaptation/Investigation.")
        return "investigating"
    
def build_soc_graph():
    builder = StateGraph(IncidentState)
    
    # 1. Add Nodes
    builder.add_node("intake", intake_node)
    builder.add_node("investigating", investigator_node)
    builder.add_node("strategist", strategist_node)
    builder.add_node("tools", ToolNode(soc_tools))
    builder.add_node("assessing", assessment_node)
    builder.add_node("defending", defense_node)
    builder.add_node("reviewing", reviewer_node)
    # 2. Add Edges (The Flow)
    builder.add_edge(START, "intake")
    builder.add_edge("intake", "investigating")
    builder.add_edge("investigating", "strategist")
    builder.add_node("executing", executor_node)
    builder.add_node("verifying", verifier_node)
    builder.add_node("postmortem", judge_node)
    builder.add_node("rart", rart_node)
    # 3. Conditional Tool Execution
    def route_tools(state: IncidentState):
        last_message = state.messages[-1]
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            return "tools"
        return "assessing"

    builder.add_conditional_edges(
        "strategist", 
        route_tools, 
        {"tools": "tools", "assessing": "assessing"}
    )
    
    # 4. Connect Tools to Assessment
    # 4. STATE 5: State Update & Sufficiency Loop
    # Instead of a direct line, we use a conditional edge to create the loop
    builder.add_conditional_edges(
        "tools",
        check_evidence_sufficiency, 
        {
            "assessing": "assessing",    # YES -> Move to State 6
            "strategist": "strategist"   # NO -> Loop back to State 3
        }
    )
    builder.add_edge("assessing", "defending")
    builder.add_edge("defending", "reviewing")
    builder.add_conditional_edges(
        "reviewing", 
        route_review, 
        {
            "executing": "executing",
            "investigating": "investigating"
        }
    )
    builder.add_edge("executing", "verifying")
    builder.add_edge("verifying", "postmortem")
    builder.add_edge("postmortem", "rart")
    builder.add_edge("rart", END)
    return builder.compile()

soc_graph = build_soc_graph()


