import json
import logging
from typing import Dict, Any, Optional, Union
from langchain_core.messages import AIMessage

from app.core.state import (
    IncidentState,
    NIDSAlert,
    MitigationEnvelope,
    ActionPayload,
)
from app.core.llm import invoke_structured_llm
from app.agents.judge import _infer_expected_threat_class

logger = logging.getLogger("Zephyr-Defense")
logger.setLevel(logging.INFO)

# =====================================================================
# CANONICAL RESPONDER SYSTEM PROMPT (Shared by Inference & GRPO Training)
# =====================================================================

RESPONDER_SYSTEM_PROMPT = """You are the Project Zephyr Autonomous SOC Responder Agent operating inside a 5-node Linux Docker LAN (`br-zephyr`: `pc-1` [172.28.0.11], `pc-2` [172.28.0.12], `pc-3` [172.28.0.13], `pc-4` [172.28.0.14], `pc-5` [172.28.0.15]).

Your task is to analyze an incoming `NIDSAlert` JSON and output a strictly validated `MitigationEnvelope` JSON object.

### STRICT OPERATIONAL & FIREWALL RULES:
1. **EXACT ENTITY GROUNDING (CHOSEN & REJECTED):**
   - Both `chosen_mitigation` AND `rejected_alternative` MUST use the EXACT same entities from the input `NIDSAlert`:
     * `target_container` == `alert.target_node`
     * `source_ip` == `alert.source_ip`
     * `dest_port` == `alert.dest_port`
   - Never invent or alter IP addresses, container names, or port numbers in either `chosen_mitigation` or `rejected_alternative`.

2. **CONTAINER IPTABLES SYNTAX & TOPOLOGY:**
   - Every command runs inside the victim container namespace (`docker exec <target_container> <iptables_cmd>`).
   - Commands MUST target the `INPUT` chain (`-A INPUT` or `-I INPUT` or `-P INPUT`).
   - NEVER use `PREROUTING`, `POSTROUTING`, `FORWARD`, `OUTPUT`, `-t nat`, `-F`, or shell operators (`;`, `&&`, `||`, `|`).
   - If `alert.protocol` is `"HTTP"` or `"TCP"`, use `-p tcp`. If `"UDP"`, use `-p udp`. If `"ICMP"`, use `-p icmp`.

3. **ACTION TYPE SEMANTICS & CANONICAL IPTABLES TEMPLATES:**
   - `BLOCK_SOURCE_IP` (Surgical single-attacker block; use for `RCE_ATTEMPT`, `SQL_INJECTION`, `SSH_BRUTE_FORCE`, `PORT_SCAN`, or `SYN_FLOOD`):
     * Template: `iptables -A INPUT -s <source_ip> -p <proto> --dport <dest_port> -j DROP`
     * `estimated_collateral_impact`: MUST be `"ZERO"` or `"LOW"`.
   - `RATE_LIMIT_SYN` (Surgical TCP SYN flood throttle; preferred for `SYN_FLOOD`):
     * Template: `iptables -A INPUT -s <source_ip> -p tcp --syn --dport <dest_port> -m limit --limit 15/s --limit-burst 30 -j ACCEPT`
     * `estimated_collateral_impact`: MUST be `"ZERO"` or `"LOW"`.
   - `DROP_PORT_TRAFFIC` (Over-broad global port block; drops the port for ALL containers—use ONLY in `rejected_alternative`):
     * Template: `iptables -A INPUT -p <proto> --dport <dest_port> -j DROP`
     * `estimated_collateral_impact`: MUST be `"MODERATE"` or `"HIGH"`.
   - `ISOLATE_NODE` (Destructive full-container lockdown—use ONLY in `rejected_alternative`):
     * Template: `iptables -P INPUT DROP`
     * `estimated_collateral_impact`: MUST be `"HIGH"`.
   - `NO_OP` (Mandatory `chosen_mitigation` when traffic is `BENIGN`):
     * Template: `# NO_OP`
     * `estimated_collateral_impact`: MUST be `"ZERO"`.

4. **LEAST-PRIVILEGE PROPORTIONALITY & REJECTED ALTERNATIVE:**
   - If the alert is `BENIGN`, `chosen_mitigation.action_type` MUST be `"NO_OP"` (`# NO_OP`, impact `"ZERO"`), and `rejected_alternative` should be a false-positive block (e.g., `BLOCK_SOURCE_IP` or `DROP_PORT_TRAFFIC`) with a clear `rejection_reason` explaining why blocking benign traffic disrupts services.
   - If the alert is malicious, `chosen_mitigation` MUST be surgical (`RATE_LIMIT_SYN` or `BLOCK_SOURCE_IP` with `"ZERO"`/`"LOW"` impact), and `rejected_alternative` MUST be a distinct, inferior action on the same `target_container`, `source_ip`, and `dest_port` (such as `DROP_PORT_TRAFFIC` or `ISOLATE_NODE` with `"HIGH"` impact).

5. **THREAT CLASSIFICATION MAPPING (`threat_classification`):**
   - `"BENIGN"`: `mitre_technique_id` is `"T0000"`, `mitre_tactic` is `"None"`, or signature indicates normal/routine/authorized/legitimate traffic.
   - `"PORT_SCAN"`: `mitre_technique_id` is `"T1046"`, `mitre_tactic` is `"Discovery"`, `unique_dest_ports` has >3 ports, or signature mentions Nmap/Port Scan/Reconnaissance.
   - `"SQL_INJECTION"`: Signature/payload indicates SQL Injection (`UNION SELECT`, `OR 1=1`) or Cross-Site Scripting (`XSS`, `T1059.007`).
   - `"SSH_BRUTE_FORCE"`: `mitre_technique_id` starts with `"T1110"` or signature indicates SSH, FTP, or Web credential brute-force/password guessing.
   - `"SYN_FLOOD"`: `mitre_tactic` is `"Impact"` (`T1498*`, `T1499*`), high-rate SYN flood, UDP flood (LOIC-UDP), or HTTP DoS flood (HULK, GoldenEye, Slowloris, SlowHTTPTest, HOIC, LOIC). Note: Only use `RATE_LIMIT_SYN` if `protocol` is `"TCP"`/`"HTTP"` AND `syn_ratio >= 0.5`; otherwise use `BLOCK_SOURCE_IP`.
   - `"RCE_ATTEMPT"`: Remote code/service execution (Log4j, Heartbleed, SMB PsExec/PowerShell, Kerberos lateral movement `T1091`, or Botnet C2 callbacks `T1071*`).
"""


def build_responder_user_prompt(
    alert: Union[NIDSAlert, Dict[str, Any]],
    critic_feedback: Optional[str] = None,
) -> str:
    """
    Constructs the standardized user prompt for a NIDSAlert.
    Appends deterministic Critic error feedback when self-correcting on retry.
    """
    alert_obj = alert if isinstance(alert, NIDSAlert) else NIDSAlert.model_validate(alert)
    alert_json_str = json.dumps(alert_obj.model_dump(), indent=2)

    prompt = (
        "### INCOMING NIDS ALERT (CONTRACT A):\n"
        f"{alert_json_str}\n\n"
        "### REQUIRED ENTITY BINDINGS:\n"
        f"- target_container: \"{alert_obj.target_node}\"\n"
        f"- source_ip: \"{alert_obj.source_ip}\"\n"
        f"- dest_port: {alert_obj.dest_port}\n"
        f"- iptables protocol flag: \"{'tcp' if alert_obj.protocol in ('TCP', 'HTTP') else alert_obj.protocol.lower()}\"\n"
    )

    if critic_feedback:
        prompt += (
            "\n### CRITICAL SELF-CORRECTION REQUIRED (PREVIOUS ATTEMPT REJECTED BY CRITIC):\n"
            f"{critic_feedback}\n"
            "Fix every error listed above and return a corrected `MitigationEnvelope` JSON object."
        )

    return prompt


# =====================================================================
# DETERMINISTIC SURGICAL FALLBACK GENERATOR (Zero-Crash Guarantee)
# =====================================================================

def build_deterministic_fallback_envelope(
    alert: Union[NIDSAlert, Dict[str, Any]],
    fallback_note: Optional[str] = None,
) -> MitigationEnvelope:
    """
    Synthesizes a 100% deterministic, schema- and syntax-valid surgical MitigationEnvelope
    directly from the NIDSAlert telemetry if the LLM is offline or exhausts Critic retries.
    """
    alert_obj = alert if isinstance(alert, NIDSAlert) else NIDSAlert.model_validate(alert)
    threat_class = _infer_expected_threat_class(alert_obj)
    proto_flag = "tcp" if alert_obj.protocol in ("TCP", "HTTP") else alert_obj.protocol.lower()
    src_ip = alert_obj.source_ip
    target_node = alert_obj.target_node
    dport = alert_obj.dest_port
    severity = alert_obj.nids_llm_assessment.severity

    if threat_class == "BENIGN":
        chosen = ActionPayload(
            action_type="NO_OP",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd="# NO_OP",
            estimated_collateral_impact="ZERO",
        )
        rejected = ActionPayload(
            action_type="BLOCK_SOURCE_IP",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd=f"iptables -A INPUT -s {src_ip} -p {proto_flag} --dport {dport} -j DROP",
            estimated_collateral_impact="MODERATE",
        )
        reasoning = (
            f"Telemetry from {alert_obj.source_node} ({src_ip}) to {target_node} ({alert_obj.target_ip}:{dport}) "
            "matches a benign traffic profile. Executing NO_OP preserves service availability with zero collateral impact."
        )
        rejection_reason = (
            f"Blocking source IP {src_ip} during benign activity would unnecessarily sever legitimate container communication."
        )
    elif threat_class == "SYN_FLOOD" and proto_flag == "tcp" and alert_obj.flow_metrics.syn_ratio >= 0.5:
        chosen = ActionPayload(
            action_type="RATE_LIMIT_SYN",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd=(
                f"iptables -A INPUT -s {src_ip} -p tcp --syn --dport {dport} "
                f"-m limit --limit 15/s --limit-burst 30 -j ACCEPT"
            ),
            estimated_collateral_impact="ZERO",
        )
        rejected = ActionPayload(
            action_type="DROP_PORT_TRAFFIC",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd=f"iptables -A INPUT -p tcp --dport {dport} -j DROP",
            estimated_collateral_impact="HIGH",
        )
        reasoning = (
            f"High-rate TCP SYN flood (syn_ratio={alert_obj.flow_metrics.syn_ratio}) detected from "
            f"{alert_obj.source_node} ({src_ip}) targeting {target_node}:{dport}. Applying a surgical INPUT chain "
            f"SYN rate-limit scoped to {src_ip} neutralizes the flood while preserving normal traffic."
        )
        rejection_reason = (
            f"Dropping TCP port {dport} globally on {target_node} would cause a denial of service for all legitimate LAN nodes."
        )
    else:
        chosen = ActionPayload(
            action_type="BLOCK_SOURCE_IP",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd=f"iptables -A INPUT -s {src_ip} -p {proto_flag} --dport {dport} -j DROP",
            estimated_collateral_impact="ZERO",
        )
        rejected = ActionPayload(
            action_type="ISOLATE_NODE",
            target_container=target_node,
            source_ip=src_ip,
            dest_port=dport,
            iptables_cmd="iptables -P INPUT DROP",
            estimated_collateral_impact="HIGH",
        )
        reasoning = (
            f"Detected {threat_class} ({alert_obj.nids_llm_assessment.attack_signature}) from "
            f"{alert_obj.source_node} ({src_ip}) targeting {target_node}:{dport}. "
            f"Surgically dropping packets from {src_ip} to port {dport} on {target_node}'s INPUT chain isolates the attacker with zero collateral impact."
        )
        rejection_reason = (
            f"Setting default INPUT policy to DROP on {target_node} (ISOLATE_NODE) severs all legitimate LAN services on the container."
        )

    if fallback_note:
        reasoning = f"{reasoning} [{fallback_note}]"

    return MitigationEnvelope(
        threat_classification=threat_class,
        severity=severity,
        reasoning_trace=reasoning,
        chosen_mitigation=chosen,
        rejected_alternative=rejected,
        rejection_reason=rejection_reason,
    )


# =====================================================================
# ACTOR INFERENCE INVOCATION
# =====================================================================

def generate_actor_proposal(
    alert: Union[NIDSAlert, Dict[str, Any]],
    critic_feedback: Optional[str] = None,
    temperature: float = 0.1,
    model_override: Optional[str] = None,
    host_override: Optional[str] = None,
) -> MitigationEnvelope:
    """
    Calls the Responder LLM (localhost:11434) with Pydantic-constrained decoding
    to produce a candidate MitigationEnvelope.
    """
    alert_obj = alert if isinstance(alert, NIDSAlert) else NIDSAlert.model_validate(alert)
    user_prompt = build_responder_user_prompt(alert_obj, critic_feedback=critic_feedback)

    return invoke_structured_llm(
        system_prompt=RESPONDER_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_model=MitigationEnvelope,
        role="responder",
        temperature=temperature,
        max_retries=2,
        model_override=model_override,
        host_override=host_override,
    )


# =====================================================================
# LANGGRAPH NODE COMPATIBILITY WRAPPER
# =====================================================================

def defense_node(state: IncidentState) -> Dict[str, Any]:
    """
    LangGraph Actor Node.
    If state.nids_alert is present, runs the Responder Actor to produce a MitigationEnvelope.
    """
    logger.info(f"[{state.incident_id}] === RESPONDER ACTOR PHASE INITIATED ===")

    if state.nids_alert is not None:
        feedback = state.reviewer_feedback if state.reviewer_decision == "REJECT" else None
        try:
            envelope = generate_actor_proposal(state.nids_alert, critic_feedback=feedback)
        except Exception as e:
            logger.warning(f"[{state.incident_id}] Actor LLM failed ({e}); activating deterministic surgical fallback.")
            envelope = build_deterministic_fallback_envelope(
                state.nids_alert, fallback_note="Deterministic fallback activated"
            )

        return {
            "status": "DEFENDING",
            "mitigation_envelope": envelope,
            "proposed_action": envelope.chosen_mitigation.action_type,
            "proposed_target": envelope.chosen_mitigation.target_container,
            "action_justification": envelope.reasoning_trace,
            "messages": [
                AIMessage(
                    content=(
                        f"Actor Proposal: {envelope.chosen_mitigation.action_type} on "
                        f"{envelope.chosen_mitigation.target_container} ({envelope.chosen_mitigation.iptables_cmd})"
                    )
                )
            ],
        }

    # Legacy fallback when called without NIDSAlert
    return {
        "status": "DEFENDING",
        "proposed_action": "BLOCK_SOURCE_IP",
        "proposed_target": state.target_ip,
        "action_justification": "Legacy state fallback strategy.",
        "messages": [AIMessage(content=f"Defense Strategy: BLOCK_SOURCE_IP on {state.target_ip}.")],
    }