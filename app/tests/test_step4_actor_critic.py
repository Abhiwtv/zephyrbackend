from unittest.mock import patch
import pytest

from app.core.state import NIDSAlert, MitigationEnvelope
from app.agents.defense import (
    RESPONDER_SYSTEM_PROMPT,
    build_responder_user_prompt,
    build_deterministic_fallback_envelope,
)
from app.agents.reviewer import (
    evaluate_with_critic,
    run_actor_critic_loop,
)


@pytest.fixture
def syn_flood_alert() -> NIDSAlert:
    return NIDSAlert.model_validate({
        "alert_id": "synthetic-syn-flood-001",
        "timestamp": "2026-10-18T17:00:00Z",
        "source_node": "pc-2",
        "source_ip": "172.28.0.12",
        "target_node": "pc-3",
        "target_ip": "172.28.0.13",
        "dest_port": 8080,
        "protocol": "TCP",
        "flow_metrics": {
            "packet_count_2s": 1200,
            "byte_count_2s": 96000,
            "syn_ratio": 0.96,
            "unique_dest_ports": [8080],
            "payload_sample": "TCP SYN flood burst to port 8080"
        },
        "nids_llm_assessment": {
            "attack_signature": "Possible SYN flood",
            "mitre_tactic": "Impact",
            "mitre_technique_id": "T1498",
            "confidence_score": 0.98,
            "severity": "HIGH",
            "raw_telemetry_summary": "1200 packets in 2s with 0.96 SYN ratio from pc-2 to pc-3:8080"
        }
    })


def test_prompt_builder_includes_entities_and_critic_feedback(syn_flood_alert):
    """Verifies canonical prompt generation for both initial pass and Critic retry pass."""
    assert "INPUT" in RESPONDER_SYSTEM_PROMPT
    assert "PREROUTING" in RESPONDER_SYSTEM_PROMPT

    base_prompt = build_responder_user_prompt(syn_flood_alert)
    assert "172.28.0.12" in base_prompt
    assert "pc-3" in base_prompt
    assert "8080" in base_prompt
    assert "CRITICAL SELF-CORRECTION REQUIRED" not in base_prompt

    retry_prompt = build_responder_user_prompt(
        syn_flood_alert,
        critic_feedback="1. chosen_mitigation.iptables_cmd must start with 'iptables'."
    )
    assert "CRITICAL SELF-CORRECTION REQUIRED" in retry_prompt
    assert "must start with 'iptables'" in retry_prompt


@patch("app.agents.reviewer.generate_actor_proposal")
def test_actor_critic_loop_approves_valid_first_attempt(mock_actor, syn_flood_alert):
    """When Actor emits a valid surgical envelope on Attempt 1, Critic approves immediately."""
    valid_env = build_deterministic_fallback_envelope(syn_flood_alert)
    mock_actor.return_value = valid_env

    result = run_actor_critic_loop(syn_flood_alert, max_critic_retries=2)

    assert mock_actor.call_count == 1
    assert result.grpo_scoring_debug is not None
    assert result.grpo_scoring_debug.total_reward == 8.0
    assert result.chosen_mitigation.action_type == "RATE_LIMIT_SYN"


@patch("app.agents.reviewer.generate_actor_proposal")
def test_actor_critic_loop_catches_and_repairs_qwen3b_findings_on_retry(mock_actor, syn_flood_alert):
    """
    Simulates Attempt 1 returning the flawed qwen2.5:3b-instruct output from Test C
    (Findings 1, 2, and 3) and verifies that the Critic rejects it, passes the exact
    error feedback to Attempt 2, and approves the repaired Attempt 2 output.
    """
    flawed_attempt_1 = MitigationEnvelope.model_validate({
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "Narrow block of source IP on port 8080.",
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "-A PREROUTING -s 172.28.0.12/32 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejected_alternative": {
            "action_type": "DROP_PORT_TRAFFIC",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 80,
            "iptables_cmd": "iptables -A INPUT -p tcp --dport 80 -j DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Dropping port 80 globally disrupts web traffic."
    })

    repaired_attempt_2 = MitigationEnvelope.model_validate({
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "Repaired: Surgical INPUT chain block of 172.28.0.12 on port 8080 with ZERO collateral impact.",
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "DROP_PORT_TRAFFIC",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Dropping port 8080 globally on pc-3 impacts all legitimate clients."
    })

    mock_actor.side_effect = [flawed_attempt_1, repaired_attempt_2]

    result = run_actor_critic_loop(syn_flood_alert, max_critic_retries=2)

    assert mock_actor.call_count == 2
    # Check that Attempt 2 received Critic feedback containing Findings 1, 2, and 3
    second_call_kwargs = mock_actor.call_args_list[1][1]
    feedback_sent = second_call_kwargs["critic_feedback"]
    assert "Critic REJECTED" in feedback_sent
    assert "iptables" in feedback_sent
    assert "rejected_alternative.dest_port (80)" in feedback_sent
    assert "estimated_collateral_impact" in feedback_sent

    assert result.grpo_scoring_debug is not None
    assert result.grpo_scoring_debug.total_reward == 8.0
    assert result.chosen_mitigation.iptables_cmd == "iptables -A INPUT -s 172.28.0.12 -p tcp --dport 8080 -j DROP"


@patch("app.agents.reviewer.generate_actor_proposal")
def test_deterministic_fallback_when_llm_offline(mock_actor, syn_flood_alert):
    """Ensures that if Ollama tunnel drops during the live demo, fallback returns a +8.0 valid envelope."""
    mock_actor.side_effect = RuntimeError("Connection refused on localhost:11434")

    result = run_actor_critic_loop(syn_flood_alert, max_critic_retries=1, use_fallback_on_failure=True)

    assert result.grpo_scoring_debug is not None
    assert result.grpo_scoring_debug.total_reward == 8.0
    assert result.chosen_mitigation.target_container == "pc-3"
    assert result.chosen_mitigation.source_ip == "172.28.0.12"


def test_deterministic_fallback_across_rce_and_benign(syn_flood_alert):
    """Verifies deterministic fallback produces +8.0 envelopes for both RCE (HTTP->tcp) and BENIGN (NO_OP)."""
    # 1. RCE over HTTP
    rce_dict = syn_flood_alert.model_dump()
    rce_dict["protocol"] = "HTTP"
    rce_dict["flow_metrics"]["syn_ratio"] = 0.1
    rce_dict["nids_llm_assessment"]["attack_signature"] = "Log4j JNDI RCE Attempt"
    rce_alert = NIDSAlert.model_validate(rce_dict)

    rce_env = build_deterministic_fallback_envelope(rce_alert)
    approved_rce, _, rep_rce = evaluate_with_critic(rce_alert, rce_env)
    assert approved_rce is True
    assert rep_rce.reward_breakdown.total_reward == 8.0
    assert "-p tcp" in rce_env.chosen_mitigation.iptables_cmd

    # 2. Benign traffic spike
    benign_dict = syn_flood_alert.model_dump()
    benign_dict["flow_metrics"]["syn_ratio"] = 0.05
    benign_dict["nids_llm_assessment"]["attack_signature"] = "Benign healthcheck spike"
    benign_dict["nids_llm_assessment"]["severity"] = "LOW"
    benign_dict["nids_llm_assessment"]["raw_telemetry_summary"] = "Normal benign traffic."
    benign_alert = NIDSAlert.model_validate(benign_dict)

    benign_env = build_deterministic_fallback_envelope(benign_alert)
    approved_benign, _, rep_benign = evaluate_with_critic(benign_alert, benign_env)
    assert approved_benign is True
    assert rep_benign.reward_breakdown.total_reward == 8.0
    assert benign_env.chosen_mitigation.action_type == "NO_OP"