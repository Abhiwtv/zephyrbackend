import logging
from typing import Literal

from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

from app.core.state import IncidentState
from app.tools.mock_env import soc_tools

# Import all agent nodes
from app.agents.intake import intake_node
from app.agents.investigator import investigator_node
from app.agents.strategist import strategist_node
from app.agents.assessment import assessment_node
from app.agents.defense import defense_node
from app.agents.reviewer import reviewer_node
from app.agents.rart import rart_node
from app.agents.executor import executor_node
from app.agents.verifier import verifier_node
from app.agents.judge import judge_node

logger = logging.getLogger("Zephyr-Orchestrator")
logger.setLevel(logging.INFO)

# --- Conditional Routing Logic ---

def route_strategist(state: IncidentState) -> Literal["tools", "assessor"]:
    """
    Checks if the Strategist generated tool calls. 
    If yes, route to the execution sandbox (tools). 
    If no (or if fallback occurred), proceed straight to assessment.
    """
    last_message = state.messages[-1]
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        logger.debug(f"[{state.incident_id}] Graph Routing: Strategist -> Tools")
        return "tools"
    
    logger.debug(f"[{state.incident_id}] Graph Routing: Strategist -> Assessor (No tools called)")
    return "assessor"


def route_reviewer(state: IncidentState) -> Literal["executor", "rart"]:
    """
    The Near-Miss Gatekeeper.
    Evaluates the Reviewer's simulation decision.
    APPROVE -> Route to Production Execution.
    REJECT -> Route to RART for Policy Mutation.
    """
    if state.reviewer_decision == "APPROVE":
        logger.info(f"[{state.incident_id}] Graph Routing: Reviewer -> Executor (Plan Approved)")
        return "executor"
    else:
        logger.warning(f"[{state.incident_id}] Graph Routing: Reviewer -> RART (Plan Rejected - Triggering Evolution Loop)")
        return "rart"

# --- Graph Construction ---

def build_soc_graph():
    """
    Constructs and compiles the LangGraph state machine.
    """
    logger.info("Building Zephyr LangGraph State Machine...")
    
    builder = StateGraph(IncidentState)
    
    # 1. Register all nodes
    builder.add_node("intake", intake_node)
    builder.add_node("investigator", investigator_node)
    builder.add_node("strategist", strategist_node)
    builder.add_node("tools", ToolNode(soc_tools))
    builder.add_node("assessor", assessment_node)
    builder.add_node("defense", defense_node)
    builder.add_node("reviewer", reviewer_node)
    builder.add_node("rart", rart_node)
    builder.add_node("executor", executor_node)
    builder.add_node("verifier", verifier_node)
    builder.add_node("judge", judge_node)
    
    # 2. Define the exact flow of execution (Edges)
    builder.add_edge(START, "intake")
    builder.add_edge("intake", "investigator")
    builder.add_edge("investigator", "strategist")
    
    # Conditional edge for tool execution
    builder.add_conditional_edges(
        "strategist", 
        route_strategist, 
        {"tools": "tools", "assessor": "assessor"}
    )
    
    # Tools feed directly into the Assessor for a final verdict
    builder.add_edge("tools", "assessor")
    builder.add_edge("assessor", "defense")
    builder.add_edge("defense", "reviewer")
    
    # The crucial evolutionary fork
    builder.add_conditional_edges(
        "reviewer", 
        route_reviewer, 
        {"executor": "executor", "rart": "rart"}
    )
    
    # If routed to RART, loop BACK to Defense to formulate a new plan
    builder.add_edge("rart", "defense")
    
    # Final execution and grading path
    builder.add_edge("executor", "verifier")
    builder.add_edge("verifier", "judge")
    builder.add_edge("judge", END)
    
    # Compile the graph
    compiled_graph = builder.compile()
    logger.info("Zephyr LangGraph compiled successfully.")
    
    return compiled_graph

# Instantiate the singleton graph used by FastAPI and training scripts
soc_graph = build_soc_graph()