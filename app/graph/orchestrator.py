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
    STATE 5: STATE_UPDATE & ROUTING (With Circuit Breaker)
    """
    # 1. CIRCUIT BREAKER: Count how many tool calls have been made
    tool_messages = [msg for msg in state.messages if msg.type == "tool"]
    
    # If the agent has tried and failed 3 times, force it forward to prevent API bans
    if len(tool_messages) >= 3:
        print("⚠️ Circuit Breaker Triggered: Max evidence attempts reached. Forcing Assessment.")
        return "assessing"

    # 2. STANDARD CHECK: If under the limit, ask the LLM if we have enough
    evidence_text = "\n".join([msg.content for msg in tool_messages])
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are the SOC Orchestrator. Review the gathered evidence. Do we have enough conclusive evidence to prove whether the SQL injection attack succeeded or failed? Answer purely based on the evidence."),
        ("user", "Missing Evidence goals: {missing}\n\nEvidence Gathered:\n{evidence}")
    ])
    
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
    
import time

def with_timer(node_func, node_name):
    def wrapper(state):
        start = time.time()
        if hasattr(node_func, "invoke"):
            result = node_func.invoke(state)
        else:
            result = node_func(state)
        end = time.time()
        print(f"[TIMER] Node '{node_name}' took {end - start:.2f} seconds")
        return result
    return wrapper

def check_evidence_sufficiency_with_timer(state: IncidentState):
    start = time.time()
    result = check_evidence_sufficiency(state)
    end = time.time()
    print(f"[TIMER] Edge 'check_evidence_sufficiency' took {end - start:.2f} seconds")
    return result

def build_soc_graph():
    builder = StateGraph(IncidentState)
    
    # 1. Add Nodes
    builder.add_node("intake", with_timer(intake_node, "intake"))
    builder.add_node("investigating", with_timer(investigator_node, "investigating"))
    builder.add_node("strategist", with_timer(strategist_node, "strategist"))
    builder.add_node("tools", ToolNode(soc_tools))
    builder.add_node("assessing", with_timer(assessment_node, "assessing"))
    builder.add_node("defending", with_timer(defense_node, "defending"))
    builder.add_node("reviewing", with_timer(reviewer_node, "reviewing"))
    builder.add_node("executing", with_timer(executor_node, "executing"))
    builder.add_node("verifying", with_timer(verifier_node, "verifying"))
    builder.add_node("postmortem", with_timer(judge_node, "postmortem"))
    builder.add_node("rart", with_timer(rart_node, "rart"))
    
    # 2. Add Edges (The Flow)
    builder.add_edge(START, "intake")
    builder.add_edge("intake", "investigating")
    builder.add_edge("investigating", "strategist")
    
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
    
    # 4. STATE 5: State Update & Sufficiency Loop
    builder.add_conditional_edges(
        "tools",
        check_evidence_sufficiency_with_timer, 
        {
            "assessing": "assessing",    
            "strategist": "strategist"   
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


