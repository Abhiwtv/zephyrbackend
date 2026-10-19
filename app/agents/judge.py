import re
import json
import shlex
import logging
from typing import Dict, Any, List, Tuple, Optional, Union
from pydantic import BaseModel, Field, ValidationError
from langchain_core.messages import AIMessage

from app.core.state import (
    IncidentState,
    NIDSAlert,
    MitigationEnvelope,
    ActionPayload,
    GRPORewardBreakdown,
    NODE_IP_MAP,
)
from app.core.llm import extract_json_payload

logger = logging.getLogger("Zephyr-Judge")
logger.setLevel(logging.INFO)

# =====================================================================
# DETERMINISTIC VALIDATION REPORT SCHEMA (For Critic & Diagnostics)
# =====================================================================

class MitigationValidationReport(BaseModel):
    is_valid: bool = Field(description="True only if schema, syntax, grounding, and semantics all pass")
    errors: List[str] = Field(default_factory=list, description="Hard errors requiring Critic self-correction")
    warnings: List[str] = Field(default_factory=list, description="Suboptimal choices that reduce GRPO reward")
    reward_breakdown: GRPORewardBreakdown


# =====================================================================
# 1. DETERMINISTIC IPTABLES SYNTAX & TOPOLOGY VALIDATOR (Fixes Finding 3)
# =====================================================================

SHELL_INJECTION_PATTERN = re.compile(r"[;&|`$><\n\r]")
ALLOWED_CHAINS = {"INPUT"}
FORBIDDEN_CHAINS = {"PREROUTING", "POSTROUTING", "FORWARD", "OUTPUT"}
FORBIDDEN_FLAGS = {"-F", "--flush", "-X", "--delete-chain", "-t"}


def _strip_cidr(ip_token: str) -> str:
    """Normalizes '172.28.0.12/32' -> '172.28.0.12' while rejecting wide CIDRs like '/16' or '/24'."""
    if "/" in ip_token:
        base_ip, prefix = ip_token.split("/", 1)
        if prefix != "32":
            return ip_token  # Keep non-/32 CIDR so grounding check flags it as over-broad
        return base_ip
    return ip_token


def validate_iptables_syntax_and_semantics(
    action: ActionPayload,
    expected_target_node: str,
    expected_src_ip: str,
    expected_dport: int,
    expected_protocol: str,
    is_chosen: bool = True,
) -> Tuple[bool, List[str], float]:
    """
    Deterministically parses and validates an ActionPayload's iptables_cmd,
    container chain topology, entity grounding, and action_type semantics.

    Returns: (is_valid, error_messages, syntax_and_grounding_subscore [-1.5 to +1.5])
    """
    errors: List[str] = []
    cmd = action.iptables_cmd.strip()
    label_prefix = "chosen_mitigation" if is_chosen else "rejected_alternative"

    # 1. Entity field grounding against NIDSAlert
    score = 0.0
    if action.target_container == expected_target_node:
        score += 0.4
    else:
        score -= 0.5
        errors.append(
            f"{label_prefix}.target_container ('{action.target_container}') does not match alert target_node ('{expected_target_node}')."
        )

    if action.source_ip == expected_src_ip:
        score += 0.4
    else:
        score -= 0.5
        errors.append(
            f"{label_prefix}.source_ip ('{action.source_ip}') does not match alert source_ip ('{expected_src_ip}')."
        )

    if action.dest_port == expected_dport:
        score += 0.2
    else:
        score -= 0.3
        errors.append(
            f"{label_prefix}.dest_port ({action.dest_port}) does not match alert dest_port ({expected_dport})."
        )

    # Verify container-to-IP topology consistency
    expected_node_ip = NODE_IP_MAP.get(action.target_container)
    if expected_node_ip and action.source_ip == expected_node_ip:
        score -= 0.5
        errors.append(
            f"{label_prefix} attempts to block target_container '{action.target_container}'s own IP ({expected_node_ip})."
        )

    # 2. Special handling for NO_OP
    if action.action_type == "NO_OP":
        normalized_noop = cmd.upper()
        if normalized_noop in {"# NO_OP", "NO_OP", "TRUE", ":", "# BENIGN - NO ACTION"} or cmd.startswith("#"):
            score += 0.5
            return len(errors) == 0, errors, max(-1.5, min(1.5, score))
        else:
            score -= 0.5
            errors.append(
                f"{label_prefix} has action_type='NO_OP' but iptables_cmd='{cmd}' is an active command instead of '# NO_OP'."
            )
            return False, errors, max(-1.5, min(1.5, score))

    # 3. Shell injection guard
    if SHELL_INJECTION_PATTERN.search(cmd):
        errors.append(f"{label_prefix}.iptables_cmd contains forbidden shell metacharacters: '{cmd}'.")
        return False, errors, -1.5

    # 4. Tokenize with shlex
    try:
        tokens = shlex.split(cmd)
    except ValueError as e:
        errors.append(f"{label_prefix}.iptables_cmd could not be parsed as valid shell tokens: {e}.")
        return False, errors, -1.5

    if not tokens:
        errors.append(f"{label_prefix}.iptables_cmd is empty.")
        return False, errors, -1.5

    # Allow optional leading 'sudo' but require 'iptables' executable (Fixes Finding 3)
    if tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens or tokens[0] != "iptables":
        errors.append(
            f"{label_prefix}.iptables_cmd must start with the 'iptables' binary (got '{tokens[0] if tokens else ''}')."
        )
        return False, errors, max(-1.5, score - 0.8)

    # 5. Check forbidden flags (-F, -X, -t nat, etc.)
    for flag in FORBIDDEN_FLAGS:
        if flag in tokens:
            errors.append(
                f"{label_prefix}.iptables_cmd uses forbidden flag '{flag}'. Rules must operate in the default container filter table."
            )
            return False, errors, max(-1.5, score - 0.8)

    # 6. Check chain specification (-A INPUT / -I INPUT / -P INPUT) (Fixes Finding 3: PREROUTING)
    chain_name: Optional[str] = None
    chain_op: Optional[str] = None
    for i, tok in enumerate(tokens):
        if tok in ("-A", "--append", "-I", "--insert", "-P", "--policy") and i + 1 < len(tokens):
            chain_op = tok
            chain_name = tokens[i + 1]
            break

    if not chain_name:
        errors.append(
            f"{label_prefix}.iptables_cmd is missing a chain operation ('-A INPUT' or '-I INPUT')."
        )
        return False, errors, max(-1.5, score - 0.6)

    if chain_name in FORBIDDEN_CHAINS or chain_name not in ALLOWED_CHAINS:
        errors.append(
            f"{label_prefix}.iptables_cmd uses invalid chain '{chain_name}'. Container-level rules must target the 'INPUT' chain."
        )
        return False, errors, max(-1.5, score - 0.6)

    # 7. Extract command parameters (-s, -p, --dport, -j)
    cmd_src_ip: Optional[str] = None
    cmd_proto: Optional[str] = None
    cmd_dport: Optional[int] = None
    cmd_jump: Optional[str] = None

    for i, tok in enumerate(tokens):
        if tok in ("-s", "--source") and i + 1 < len(tokens):
            cmd_src_ip = _strip_cidr(tokens[i + 1])
        elif tok in ("-p", "--protocol") and i + 1 < len(tokens):
            cmd_proto = tokens[i + 1].lower()
        elif tok in ("--dport", "--destination-port") and i + 1 < len(tokens):
            try:
                cmd_dport = int(tokens[i + 1])
            except ValueError:
                errors.append(f"{label_prefix}.iptables_cmd has non-integer --dport '{tokens[i + 1]}'.")
        elif tok in ("-j", "--jump") and i + 1 < len(tokens):
            cmd_jump = tokens[i + 1].upper()

    # Validate jump target
    if chain_op in ("-P", "--policy"):
        if action.action_type != "ISOLATE_NODE":
            errors.append(
                f"{label_prefix}.iptables_cmd uses default policy '-P' for action_type '{action.action_type}' (only valid for ISOLATE_NODE)."
            )
    else:
        if cmd_jump not in {"DROP", "REJECT", "ACCEPT"}:
            errors.append(
                f"{label_prefix}.iptables_cmd must include a valid jump target ('-j DROP', '-j REJECT', or '-j ACCEPT')."
            )

    # 8. Validate Action-to-Command Semantic Consistency (Fixes Finding 1)
    if action.action_type == "BLOCK_SOURCE_IP":
        if cmd_src_ip != expected_src_ip:
            errors.append(
                f"{label_prefix} (BLOCK_SOURCE_IP) must specify '-s {expected_src_ip}' in iptables_cmd (got '{cmd_src_ip}')."
            )
        if cmd_dport is not None and cmd_dport != expected_dport:
            errors.append(
                f"{label_prefix}.iptables_cmd specifies '--dport {cmd_dport}' which does not match alert dest_port ({expected_dport})."
            )
        if cmd_jump not in {"DROP", "REJECT"}:
            errors.append(
                f"{label_prefix} (BLOCK_SOURCE_IP) must jump to DROP or REJECT (got '{cmd_jump}')."
            )

    elif action.action_type == "RATE_LIMIT_SYN":
        if cmd_src_ip is not None and cmd_src_ip != expected_src_ip:
            errors.append(
                f"{label_prefix} (RATE_LIMIT_SYN) specifies wrong source IP '{cmd_src_ip}' (expected '{expected_src_ip}')."
            )
        if cmd_proto != "tcp":
            errors.append(f"{label_prefix} (RATE_LIMIT_SYN) must specify '-p tcp'.")
        if cmd_dport is not None and cmd_dport != expected_dport:
            errors.append(
                f"{label_prefix} (RATE_LIMIT_SYN) specifies '--dport {cmd_dport}' instead of {expected_dport}."
            )
        has_limit_module = ("limit" in tokens or "hashlimit" in tokens or "--syn" in tokens)
        if not has_limit_module:
            errors.append(
                f"{label_prefix} (RATE_LIMIT_SYN) must include '--syn' and '-m limit' (or '-m hashlimit') in iptables_cmd."
            )

    elif action.action_type == "DROP_PORT_TRAFFIC":
        if cmd_dport != expected_dport:
            errors.append(
                f"{label_prefix} (DROP_PORT_TRAFFIC) must specify '--dport {expected_dport}' (got '{cmd_dport}')."
            )
        if cmd_src_ip is not None and is_chosen:
            errors.append(
                f"{label_prefix} is labeled DROP_PORT_TRAFFIC (global port block) but includes '-s {cmd_src_ip}' (which is BLOCK_SOURCE_IP)."
            )

    elif action.action_type == "ISOLATE_NODE":
        if cmd_src_ip is not None or cmd_dport is not None:
            errors.append(
                f"{label_prefix} is labeled ISOLATE_NODE (full container lockdown) but scopes to IP/port ('{cmd}')."
            )

    if not errors:
        score += 0.5
    else:
        score -= 0.5

    return len(errors) == 0, errors, max(-1.5, min(1.5, score))


# =====================================================================
# 2. THREAT-TO-MITIGATION PROPORTIONALITY & COLLATERAL SCORER
# =====================================================================

def _infer_expected_threat_class(alert: NIDSAlert) -> str:
    """Infers canonical threat class from NIDSAlert assessment & telemetry."""
    sig = alert.nids_llm_assessment.attack_signature.upper()
    summary = alert.nids_llm_assessment.raw_telemetry_summary.upper()
    payload = alert.flow_metrics.payload_sample.upper()
    combined = f"{sig} {summary} {payload}"

    if "BENIGN" in combined or "NORMAL" in combined or "HEALTH" in combined:
        return "BENIGN"
    if "SYN" in combined or alert.flow_metrics.syn_ratio >= 0.8:
        return "SYN_FLOOD"
    if any(k in combined for k in ("SQL", "UNION SELECT", "OR 1=1", "SQLI")) or alert.dest_port == 3306:
        return "SQL_INJECTION"
    if any(k in combined for k in ("JNDI", "LOG4J", "RCE", "REMOTE CODE")):
        return "RCE_ATTEMPT"
    if any(k in combined for k in ("SCAN", "NMAP", "MASSCAN")) or len(alert.flow_metrics.unique_dest_ports) > 3:
        return "PORT_SCAN"
    if any(k in combined for k in ("SSH", "BRUTE", "HYDRA")) or alert.dest_port == 22:
        return "SSH_BRUTE_FORCE"
    return "RCE_ATTEMPT"


def evaluate_surgical_precision(
    alert: NIDSAlert,
    envelope: MitigationEnvelope,
) -> Tuple[float, List[str], List[str]]:
    """
    Computes surgical_precision_score in [-3.0, +3.0] and collects semantic errors/warnings.
    Enforces:
      - Benign traffic -> NO_OP with ZERO impact (+3.0) vs blocking benign traffic (-3.0)
      - Attack traffic -> Surgical least-privilege action (+2.0)
      - Collateral impact label accuracy (Fixes Finding 1) (+0.5)
      - Distinct & grounded rejected_alternative comparison (Fixes Finding 2) (+0.5)
    """
    errors: List[str] = []
    warnings: List[str] = []
    chosen = envelope.chosen_mitigation
    rejected = envelope.rejected_alternative
    expected_class = _infer_expected_threat_class(alert)
    is_benign = expected_class == "BENIGN" or envelope.threat_classification == "BENIGN"

    precision_score = 0.0

    # --- A. Benign vs Malicious Proportionality ---
    if is_benign:
        if chosen.action_type == "NO_OP":
            precision_score += 2.0
            if chosen.estimated_collateral_impact == "ZERO":
                precision_score += 0.5
            else:
                errors.append("NO_OP on benign traffic must have estimated_collateral_impact='ZERO'.")
                precision_score -= 0.5
        else:
            errors.append(
                f"Alert is BENIGN, but chosen_mitigation executed '{chosen.action_type}' instead of 'NO_OP'."
            )
            precision_score -= 3.0
    else:
        # Malicious traffic
        if chosen.action_type == "NO_OP":
            errors.append(
                f"Alert is malicious ({expected_class}), but chosen_mitigation selected 'NO_OP'."
            )
            precision_score -= 3.0
        elif expected_class == "SYN_FLOOD":
            if chosen.action_type in ("RATE_LIMIT_SYN", "BLOCK_SOURCE_IP"):
                precision_score += 2.0
            elif chosen.action_type == "DROP_PORT_TRAFFIC":
                warnings.append("DROP_PORT_TRAFFIC blocks all legitimate users on the port during a single-source SYN flood.")
                precision_score -= 1.5
                errors.append("Over-broad mitigation: use RATE_LIMIT_SYN or BLOCK_SOURCE_IP instead of DROP_PORT_TRAFFIC.")
            elif chosen.action_type == "ISOLATE_NODE":
                errors.append("Over-broad mitigation: ISOLATE_NODE severs the entire container during a single-source SYN flood.")
                precision_score -= 2.5
        else:
            # RCE_ATTEMPT, SQL_INJECTION, SSH_BRUTE_FORCE, PORT_SCAN
            if chosen.action_type == "BLOCK_SOURCE_IP":
                precision_score += 2.0
            elif chosen.action_type == "RATE_LIMIT_SYN":
                errors.append(
                    f"RATE_LIMIT_SYN is inappropriate for payload/auth attack '{expected_class}'; use BLOCK_SOURCE_IP."
                )
                precision_score -= 1.5
            elif chosen.action_type in ("DROP_PORT_TRAFFIC", "ISOLATE_NODE"):
                errors.append(
                    f"Over-broad mitigation '{chosen.action_type}' causes unnecessary collateral outage; use surgical BLOCK_SOURCE_IP."
                )
                precision_score -= 2.0

        # --- B. Collateral Impact Label Accuracy (Fixes Finding 1) ---
        if chosen.action_type in ("BLOCK_SOURCE_IP", "RATE_LIMIT_SYN"):
            if chosen.estimated_collateral_impact in ("ZERO", "LOW"):
                precision_score += 0.5
            else:
                errors.append(
                    f"chosen_mitigation '{chosen.action_type}' scopes only to attacker IP {chosen.source_ip}, "
                    f"so estimated_collateral_impact must be 'ZERO' or 'LOW' (got '{chosen.estimated_collateral_impact}')."
                )
                precision_score -= 0.5
        elif chosen.action_type == "DROP_PORT_TRAFFIC":
            if chosen.estimated_collateral_impact not in ("MODERATE", "HIGH"):
                errors.append("DROP_PORT_TRAFFIC affects all clients and must be rated 'MODERATE' or 'HIGH' collateral impact.")
                precision_score -= 0.5
        elif chosen.action_type == "ISOLATE_NODE":
            if chosen.estimated_collateral_impact != "HIGH":
                errors.append("ISOLATE_NODE severs all container traffic and must have estimated_collateral_impact='HIGH'.")
                precision_score -= 0.5

    # --- C. Rejected Alternative Contrast Quality (Fixes Finding 2) ---
    if rejected.action_type == chosen.action_type:
        errors.append(
            f"rejected_alternative.action_type ('{rejected.action_type}') must differ from chosen_mitigation.action_type."
        )
        precision_score -= 0.5
    elif len(envelope.rejection_reason.strip()) < 15:
        errors.append("rejection_reason is too brief; explain why the rejected action is suboptimal.")
        precision_score -= 0.25
    else:
        precision_score += 0.5

    return max(-3.0, min(3.0, round(precision_score, 2))), errors, warnings


# =====================================================================
# 3. MASTER VALIDATION & GRPO SCORING ENTRYPOINT
# =====================================================================

def validate_and_score_mitigation(
    nids_alert: Union[NIDSAlert, Dict[str, Any]],
    raw_or_parsed_response: Union[str, Dict[str, Any], MitigationEnvelope],
) -> MitigationValidationReport:
    """
    Master deterministic validator and GRPO reward calculator.
    Used by:
      1. The Critic node (Step 4) to decide whether to approve or trigger a self-repair retry.
      2. generate_mitigation() (Step 5) to populate `grpo_scoring_debug`.
      3. Shaurya's Unsloth GRPOTrainer loop to score rollout completions.
    """
    alert = (
        nids_alert
        if isinstance(nids_alert, NIDSAlert)
        else NIDSAlert.model_validate(nids_alert)
    )

    errors: List[str] = []
    warnings: List[str] = []

    # --- STAGE 1: Schema Compliance Score [-2.0 to +2.0] ---
    envelope: Optional[MitigationEnvelope] = None
    if isinstance(raw_or_parsed_response, MitigationEnvelope):
        envelope = raw_or_parsed_response
        schema_score = 2.0
    elif isinstance(raw_or_parsed_response, dict):
        try:
            envelope = MitigationEnvelope.model_validate(raw_or_parsed_response)
            schema_score = 2.0
        except ValidationError as val_err:
            errors.append(f"Pydantic schema validation failed: {val_err}")
            schema_score = -1.0
    elif isinstance(raw_or_parsed_response, str):
        try:
            json_str = extract_json_payload(raw_or_parsed_response)
            parsed_dict = json.loads(json_str)
            try:
                envelope = MitigationEnvelope.model_validate(parsed_dict)
                schema_score = 2.0
            except ValidationError as val_err:
                errors.append(f"JSON parsed, but MitigationEnvelope validation failed: {val_err}")
                schema_score = -1.0
        except Exception as parse_err:
            errors.append(f"Malformed JSON output: {parse_err}")
            schema_score = -2.0
    else:
        errors.append(f"Unsupported response type: {type(raw_or_parsed_response)}")
        schema_score = -2.0

    # Early return if schema failed completely
    if envelope is None:
        breakdown = GRPORewardBreakdown(
            schema_compliance_score=schema_score,
            entity_grounding_score=-3.0,
            surgical_precision_score=-3.0,
            total_reward=max(-8.0, schema_score - 6.0),
        )
        return MitigationValidationReport(
            is_valid=False,
            errors=errors,
            warnings=warnings,
            reward_breakdown=breakdown,
        )

    # --- STAGE 2: Entity Grounding & Syntax Score [-3.0 to +3.0] ---
    # Validate chosen_mitigation (contributes [-1.5, +1.5] scaled to [-2.25, +2.25])
    chosen_ok, chosen_errs, chosen_subscore = validate_iptables_syntax_and_semantics(
        action=envelope.chosen_mitigation,
        expected_target_node=alert.target_node,
        expected_src_ip=alert.source_ip,
        expected_dport=alert.dest_port,
        expected_protocol=alert.protocol,
        is_chosen=True,
    )
    errors.extend(chosen_errs)

    # Validate rejected_alternative grounding (contributes [-0.75, +0.75]) (Fixes Finding 2)
    rej_ok, rej_errs, rej_subscore = validate_iptables_syntax_and_semantics(
        action=envelope.rejected_alternative,
        expected_target_node=alert.target_node,
        expected_src_ip=alert.source_ip,
        expected_dport=alert.dest_port,
        expected_protocol=alert.protocol,
        is_chosen=False,
    )
    errors.extend(rej_errs)

    raw_grounding = (chosen_subscore * 1.5) + (rej_subscore * 0.5)
    entity_grounding_score = max(-3.0, min(3.0, round(raw_grounding, 2)))

    # --- STAGE 3: Surgical Precision Score [-3.0 to +3.0] ---
    surgical_precision_score, prec_errs, prec_warns = evaluate_surgical_precision(alert, envelope)
    errors.extend(prec_errs)
    warnings.extend(prec_warns)

    total_reward = max(
        -8.0,
        min(8.0, round(schema_score + entity_grounding_score + surgical_precision_score, 2)),
    )

    breakdown = GRPORewardBreakdown(
        schema_compliance_score=schema_score,
        entity_grounding_score=entity_grounding_score,
        surgical_precision_score=surgical_precision_score,
        total_reward=total_reward,
    )

    is_valid = (
        len(errors) == 0
        and schema_score == 2.0
        and entity_grounding_score >= 2.5
        and surgical_precision_score >= 2.0
    )

    return MitigationValidationReport(
        is_valid=is_valid,
        errors=errors,
        warnings=warnings,
        reward_breakdown=breakdown,
    )


def score_mitigation(
    nids_alert: Union[NIDSAlert, Dict[str, Any]],
    raw_or_parsed_response: Union[str, Dict[str, Any], MitigationEnvelope],
) -> GRPORewardBreakdown:
    """Convenience function returning only the Contract B GRPORewardBreakdown."""
    return validate_and_score_mitigation(nids_alert, raw_or_parsed_response).reward_breakdown


# =====================================================================
# 4. UNSLOTH GRPO TRAINER REWARD WRAPPERS (For Teammate #2 Shaurya)
# =====================================================================

def _extract_completion_text(completion: Any) -> str:
    """Handles both string completions and conversational list[{"role", "content"}] completions in TRL/Unsloth."""
    if isinstance(completion, str):
        return completion
    if isinstance(completion, list) and len(completion) > 0:
        last_msg = completion[-1]
        if isinstance(last_msg, dict):
            return str(last_msg.get("content", ""))
    return str(completion)


def grpo_total_reward_func(
    prompts: List[Any],
    completions: List[Any],
    nids_alerts: List[Union[Dict[str, Any], str]],
    **kwargs: Any,
) -> List[float]:
    """
    Unsloth / TRL GRPOTrainer compatible reward function.
    Expects dataset rows to include a `nids_alerts` column (dict or JSON string).
    Returns `total_reward` in [-8.0, +8.0] for each rollout completion.
    """
    rewards: List[float] = []
    for comp, alert_item in zip(completions, nids_alerts):
        alert_obj = json.loads(alert_item) if isinstance(alert_item, str) else alert_item
        comp_text = _extract_completion_text(comp)
        breakdown = score_mitigation(alert_obj, comp_text)
        rewards.append(breakdown.total_reward)
    return rewards


# =====================================================================
# 5. LEGACY LANGGRAPH NODE (Preserved for Backward Compatibility)
# =====================================================================

def judge_node(state: IncidentState) -> Dict[str, Any]:
    """
    Deterministic evaluation node for LangGraph.
    Uses validate_and_score_mitigation if Contract A & B payloads are present on state,
    falling back to deterministic heuristic scoring for legacy state runs.
    """
    logger.info(f"[{state.incident_id}] === DETERMINISTIC EVALUATION & SCORING INITIATED ===")

    if state.nids_alert and state.mitigation_envelope:
        report = validate_and_score_mitigation(state.nids_alert, state.mitigation_envelope)
        state.mitigation_envelope.grpo_scoring_debug = report.reward_breakdown
        return {
            "status": "COMPLETED",
            "mitigation_envelope": state.mitigation_envelope,
            "judge_scorecard": report.reward_breakdown.model_dump(),
            "messages": [
                AIMessage(
                    content=f"Judge Verdict: Valid={report.is_valid} | Total GRPO Reward={report.reward_breakdown.total_reward}/8.0"
                )
            ],
        }

    # Legacy fallback for old curriculum runs
    fallback = {
        "containment_score": 100 if state.reviewer_decision == "APPROVE" else 50,
        "blast_radius_score": 90,
        "adaptation_bonus": bool(state.learned_rule),
        "final_verdict": "Completed deterministic evaluation.",
    }
    return {
        "status": "COMPLETED",
        "judge_scorecard": fallback,
        "messages": [AIMessage(content="Judge Verdict: Completed.")],
    }