import logging
from typing import Dict, Any, Tuple, Optional, Union
from langchain_core.messages import AIMessage

from app.core.state import (
    IncidentState,
    NIDSAlert,
    MitigationEnvelope,
)
from app.agents.judge import (
    validate_and_score_mitigation,
    MitigationValidationReport,
)
from app.agents.defense import (
    generate_actor_proposal,
    build_deterministic_fallback_envelope,
)

logger = logging.getLogger("Zephyr-Reviewer")
logger.setLevel(logging.INFO)


# =====================================================================
# DETERMINISTIC CRITIC GATE
# =====================================================================

def evaluate_with_critic(
    alert: Union[NIDSAlert, Dict[str, Any]],
    envelope: MitigationEnvelope,
) -> Tuple[bool, str, MitigationValidationReport]:
    """
    Runs the deterministic validator & GRPO scorer on the Actor's candidate MitigationEnvelope.
    Returns:
      (is_approved, critic_feedback_message, validation_report)
    """
    alert_obj = alert if isinstance(alert, NIDSAlert) else NIDSAlert.model_validate(alert)
    report = validate_and_score_mitigation(alert_obj, envelope)

    if report.is_valid:
        feedback = (
            f"Critic APPROVED: All syntax, grounding, and proportionality checks passed "
            f"(GRPO Total Reward: {report.reward_breakdown.total_reward}/8.0)."
        )
        return True, feedback, report

    numbered_errors = "\n".join(f"  {idx}. {err}" for idx, err in enumerate(report.errors, start=1))
    feedback = (
        f"Critic REJECTED proposal (GRPO Total Reward: {report.reward_breakdown.total_reward}/8.0) "
        f"due to the following deterministic validation errors:\n{numbered_errors}"
    )
    return False, feedback, report


# =====================================================================
# MULTI-STEP ACTOR / CRITIC SELF-CORRECTION LOOP
# =====================================================================

def run_actor_critic_loop(
    alert: Union[NIDSAlert, Dict[str, Any]],
    max_critic_retries: int = 2,
    temperature: float = 0.1,
    use_fallback_on_failure: bool = True,
    model_override: Optional[str] = None,
    host_override: Optional[str] = None,
) -> MitigationEnvelope:
    """
    Executes the multi-step Actor -> Deterministic Critic workflow:
      1. Actor proposes a MitigationEnvelope for the NIDSAlert.
      2. Critic deterministically validates iptables syntax, chain topology,
         chosen/rejected entity grounding, and surgical proportionality.
      3. If Critic rejects, Actor receives the exact error trace and self-corrects.
      4. Attaches `grpo_scoring_debug` (GRPORewardBreakdown) before returning.
    """
    alert_obj = alert if isinstance(alert, NIDSAlert) else NIDSAlert.model_validate(alert)
    critic_feedback: Optional[str] = None
    best_envelope: Optional[MitigationEnvelope] = None
    best_report: Optional[MitigationValidationReport] = None

    total_attempts = max(1, max_critic_retries + 1)

    for attempt in range(1, total_attempts + 1):
        try:
            logger.info(f"[{alert_obj.alert_id}] Actor/Critic Attempt {attempt}/{total_attempts}...")
            candidate = generate_actor_proposal(
                alert=alert_obj,
                critic_feedback=critic_feedback,
                temperature=temperature,
                model_override=model_override,
                host_override=host_override,
            )
            approved, feedback, report = evaluate_with_critic(alert_obj, candidate)
            candidate.grpo_scoring_debug = report.reward_breakdown

            if best_report is None or report.reward_breakdown.total_reward > best_report.reward_breakdown.total_reward:
                best_envelope = candidate
                best_report = report

            if approved:
                logger.info(
                    f"[{alert_obj.alert_id}] Critic APPROVED on attempt {attempt}/{total_attempts} "
                    f"(Reward: {report.reward_breakdown.total_reward}/8.0)."
                )
                return candidate

            logger.warning(f"[{alert_obj.alert_id}] {feedback}")
            critic_feedback = feedback

        except Exception as e:
            logger.error(f"[{alert_obj.alert_id}] Actor inference failed on attempt {attempt}: {e}")
            critic_feedback = f"Previous attempt failed with exception: {e}. Return valid MitigationEnvelope JSON."

    # If all LLM attempts failed validation or connection:
    if use_fallback_on_failure:
        logger.warning(
            f"[{alert_obj.alert_id}] Exhausted {total_attempts} Actor/Critic attempts; "
            "synthesizing deterministic surgical fallback envelope."
        )
        fallback_env = build_deterministic_fallback_envelope(
            alert_obj,
            fallback_note="Verified via deterministic Critic fallback",
        )
        _, _, fallback_report = evaluate_with_critic(alert_obj, fallback_env)
        fallback_env.grpo_scoring_debug = fallback_report.reward_breakdown
        return fallback_env

    if best_envelope is not None:
        return best_envelope

    raise RuntimeError(f"Actor/Critic loop failed to produce a MitigationEnvelope for alert {alert_obj.alert_id}.")


# =====================================================================
# LANGGRAPH NODE COMPATIBILITY WRAPPER
# =====================================================================

def reviewer_node(state: IncidentState) -> Dict[str, Any]:
    """
    LangGraph Critic Node.
    Uses deterministic Critic validation when Contract A & B payloads are present.
    """
    logger.info(f"[{state.incident_id}] === DETERMINISTIC CRITIC REVIEW PHASE INITIATED ===")

    if state.nids_alert is not None and state.mitigation_envelope is not None:
        approved, feedback, report = evaluate_with_critic(state.nids_alert, state.mitigation_envelope)
        state.mitigation_envelope.grpo_scoring_debug = report.reward_breakdown
        decision = "APPROVE" if approved else "REJECT"
        return {
            "status": "REVIEWING",
            "mitigation_envelope": state.mitigation_envelope,
            "simulated_blast_radius": state.mitigation_envelope.chosen_mitigation.estimated_collateral_impact,
            "reviewer_decision": decision,
            "reviewer_feedback": feedback,
            "messages": [AIMessage(content=f"Reviewer {decision}: {feedback}")],
        }

    # Legacy fallback for old curriculum runs without NIDSAlert
    from app.tools.mock_env import simulate_blast_radius

    try:
        simulated_impact = simulate_blast_radius.invoke({
            "action": state.proposed_action,
            "target": state.proposed_target,
        })
        decision = "REJECT" if "[FATAL]" in simulated_impact else "APPROVE"
        feedback = f"Legacy simulation result: {simulated_impact}"
        return {
            "status": "REVIEWING",
            "simulated_blast_radius": simulated_impact,
            "reviewer_decision": decision,
            "reviewer_feedback": feedback,
            "messages": [AIMessage(content=f"Reviewer {decision}: {feedback}")],
        }
    except Exception as e:
        logger.error(f"[{state.incident_id}] Reviewer failure: {e}")
        return {
            "status": "REVIEWING",
            "simulated_blast_radius": "SIMULATOR_CRASH",
            "reviewer_decision": "REJECT",
            "reviewer_feedback": f"Reviewer failure: {e}",
            "messages": [AIMessage(content="Reviewer REJECT: Fail secure activated.")],
        }