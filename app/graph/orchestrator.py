import os
import json
import logging
from datetime import datetime, timezone
from typing import Literal, Dict, Any, Optional, Union

from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

from app.core.state import (
    IncidentState,
    NIDSAlert,
    MitigationEnvelope,
)
from app.tools.mock_env import soc_tools

# Import all agent nodes
from app.agents.intake import intake_node
from app.agents.investigator import investigator_node
from app.agents.strategist import strategist_node
from app.agents.assessment import assessment_node
from app.agents.defense import (
    defense_node,
    build_responder_user_prompt,
)
from app.agents.reviewer import (
    reviewer_node,
    run_actor_critic_loop,
)
from app.agents.rart import rart_node
from app.agents.executor import executor_node
from app.agents.verifier import verifier_node
from app.agents.judge import (
    judge_node,
    validate_and_score_mitigation,
)

logger = logging.getLogger("Zephyr-Orchestrator")
logger.setLevel(logging.INFO)

DEFAULT_LIVE_PREFERENCES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "dpo_dataset", "live_preferences.jsonl")
)


# =====================================================================
# STAGE 5 DATA FLYWHEEL: PREFERENCE PAIR FORMATTER & LOGGER
# =====================================================================

def format_preference_pair(
    nids_alert: Union[NIDSAlert, Dict[str, Any]],
    mitigation_envelope: Union[MitigationEnvelope, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Formats a validated NIDSAlert (Contract A) and MitigationEnvelope (Contract B)
    into a {prompt, chosen, rejected} preference record for live_preferences.jsonl.
    """
    alert_obj = (
        nids_alert
        if isinstance(nids_alert, NIDSAlert)
        else NIDSAlert.model_validate(nids_alert)
    )
    env_obj = (
        mitigation_envelope
        if isinstance(mitigation_envelope, MitigationEnvelope)
        else MitigationEnvelope.model_validate(mitigation_envelope)
    )

    prompt_str = build_responder_user_prompt(alert_obj)

    chosen_payload = {
        "threat_classification": env_obj.threat_classification,
        "severity": env_obj.severity,
        "reasoning_trace": env_obj.reasoning_trace,
        "action": env_obj.chosen_mitigation.model_dump(),
    }

    rejected_payload = {
        "threat_classification": env_obj.threat_classification,
        "severity": env_obj.severity,
        "rejection_reason": env_obj.rejection_reason,
        "action": env_obj.rejected_alternative.model_dump(),
    }

    return {
        "prompt": prompt_str,
        "chosen": json.dumps(chosen_payload),
        "rejected": json.dumps(rejected_payload),
        "metadata": {
            "alert_id": alert_obj.alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_node": alert_obj.source_node,
            "target_node": alert_obj.target_node,
            "threat_classification": env_obj.threat_classification,
            "grpo_scoring_debug": (
                env_obj.grpo_scoring_debug.model_dump()
                if env_obj.grpo_scoring_debug
                else None
            ),
        },
    }


def append_live_preference(
    nids_alert: Union[NIDSAlert, Dict[str, Any]],
    mitigation_envelope: Union[MitigationEnvelope, Dict[str, Any]],
    filepath: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Appends a {prompt, chosen, rejected} preference pair to live_preferences.jsonl
    and returns the logged dictionary so FastAPI can broadcast it over WebSockets.
    """
    target_path = filepath or DEFAULT_LIVE_PREFERENCES_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    record = format_preference_pair(nids_alert, mitigation_envelope)
    with open(target_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return record


# =====================================================================
# TEAMMATE #1 DELIVERABLE #3: UNIFIED RESPONDER ENTRYPOINT
# =====================================================================

def generate_mitigation(
    nids_alert: dict,
    *,
    max_critic_retries: int = 2,
    temperature: float = 0.1,
    use_fallback_on_failure: bool = True,
    model_override: Optional[str] = None,
    host_override: Optional[str] = None,
    log_preference: bool = False,
    preference_log_path: Optional[str] = None,
) -> dict:
    """
    Primary Responder entrypoint for FastAPI backend integration and offline GRPO rollouts.

    Consumes a NIDSAlert dict (Contract A), executes the multi-step Actor/Critic workflow,
    attaches deterministic GRPORewardBreakdown scoring, and returns a validated
    MitigationEnvelope dict (Contract B).
    """
    alert_obj = (
        nids_alert
        if isinstance(nids_alert, NIDSAlert)
        else NIDSAlert.model_validate(nids_alert)
    )

    envelope = run_actor_critic_loop(
        alert=alert_obj,
        max_critic_retries=max_critic_retries,
        temperature=temperature,
        use_fallback_on_failure=use_fallback_on_failure,
        model_override=model_override,
        host_override=host_override,
    )

    # Ensure grpo_scoring_debug is always populated on the returned envelope
    if envelope.grpo_scoring_debug is None:
        report = validate_and_score_mitigation(alert_obj, envelope)
        envelope.grpo_scoring_debug = report.reward_breakdown

    if log_preference:
        append_live_preference(alert_obj, envelope, filepath=preference_log_path)

    return envelope.model_dump()


# =====================================================================
# LEGACY LANGGRAPH STATE MACHINE (Preserved for Backward Compatibility)
# =====================================================================

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

    builder.add_conditional_edges(
        "strategist",
        route_strategist,
        {"tools": "tools", "assessor": "assessor"},
    )

    builder.add_edge("tools", "assessor")
    builder.add_edge("assessor", "defense")
    builder.add_edge("defense", "reviewer")

    builder.add_conditional_edges(
        "reviewer",
        route_reviewer,
        {"executor": "executor", "rart": "rart"},
    )

    builder.add_edge("rart", "defense")

    builder.add_edge("executor", "verifier")
    builder.add_edge("verifier", "judge")
    builder.add_edge("judge", END)

    compiled_graph = builder.compile()
    logger.info("Zephyr LangGraph compiled successfully.")

    return compiled_graph


soc_graph = build_soc_graph()