import json
import pytest

from app.core.state import NIDSAlert, MitigationEnvelope
from app.agents.judge import (
    validate_and_score_mitigation,
    score_mitigation,
    grpo_total_reward_func,
)


@pytest.fixture
def synthetic_syn_flood_alert() -> NIDSAlert:
    """Exact synthetic alert from Section 5.1 of the Diagnostic Report."""
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


def test_catches_live_qwen3b_diagnostic_findings_1_2_and_3(synthetic_syn_flood_alert):
    """
    REGRESSION TEST FOR SECTION 6 DIAGNOSTIC FINDINGS:
    Reproduces the exact flawed output from qwen2.5:3b-instruct during Test C:
      - Finding 1: BLOCK_SOURCE_IP labeled with 'HIGH' collateral impact
      - Finding 2: rejected_alternative changed dest_port from 8080 to 80
      - Finding 3: iptables_cmd omitted 'iptables' binary and used '-A PREROUTING'
    Verifies that validate_and_score_mitigation flags all three issues and marks is_valid=False.
    """
    flawed_live_output = {
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
    }

    report = validate_and_score_mitigation(synthetic_syn_flood_alert, flawed_live_output)

    assert report.is_valid is False
    joined_errors = " | ".join(report.errors)

    # Finding 3 caught: missing 'iptables' prefix
    assert "must start with the 'iptables' binary" in joined_errors
    # Finding 2 caught: rejected_alternative dest_port (80) != alert dest_port (8080)
    assert "rejected_alternative.dest_port (80) does not match alert dest_port (8080)" in joined_errors
    # Finding 1 caught: BLOCK_SOURCE_IP labeled as HIGH collateral impact
    assert "estimated_collateral_impact must be 'ZERO' or 'LOW'" in joined_errors


def test_catches_invalid_prerouting_chain_even_with_iptables_prefix(synthetic_syn_flood_alert):
    """Verifies Finding 3 chain topology check: 'iptables -A PREROUTING ...' is rejected."""
    bad_chain_envelope = {
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "Blocking source IP.",
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A PREROUTING -s 172.28.0.12 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "ISOLATE_NODE",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -P INPUT DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Full container lockdown disconnects legitimate peers."
    }

    report = validate_and_score_mitigation(synthetic_syn_flood_alert, bad_chain_envelope)
    assert report.is_valid is False
    assert any("invalid chain 'PREROUTING'" in err for err in report.errors)


def test_perfect_surgical_syn_flood_mitigation_scores_max_reward(synthetic_syn_flood_alert):
    """Verifies that a surgical, properly grounded MitigationEnvelope achieves +8.0/8.0 total reward."""
    perfect_envelope = {
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": (
            "pc-2 (172.28.0.12) is flooding pc-3 (172.28.0.13) on TCP port 8080 with a 0.96 SYN ratio. "
            "Applying a surgical RATE_LIMIT_SYN rule on pc-3's INPUT chain throttles the SYN flood from 172.28.0.12 "
            "without impacting pc-1, pc-4, or pc-5."
        ),
        "chosen_mitigation": {
            "action_type": "RATE_LIMIT_SYN",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --syn --dport 8080 -m limit --limit 15/s --limit-burst 30 -j ACCEPT",
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
        "rejection_reason": "Dropping TCP port 8080 globally on pc-3 denies service to all legitimate containers on br-zephyr."
    }

    report = validate_and_score_mitigation(synthetic_syn_flood_alert, perfect_envelope)
    assert report.is_valid is True
    assert report.errors == []
    assert report.reward_breakdown.schema_compliance_score == 2.0
    assert report.reward_breakdown.entity_grounding_score == 3.0
    assert report.reward_breakdown.surgical_precision_score == 3.0
    assert report.reward_breakdown.total_reward == 8.0


def test_benign_traffic_requires_noop_and_penalizes_blocking(synthetic_syn_flood_alert):
    """Verifies Contract A/B rule for the 15% benign traffic spikes: NO_OP scores +8.0, blocking is penalized."""
    benign_dict = synthetic_syn_flood_alert.model_dump()
    benign_dict["flow_metrics"]["syn_ratio"] = 0.05
    benign_dict["nids_llm_assessment"] = {
        "attack_signature": "Benign HTTP healthcheck spike",
        "mitre_tactic": "None",
        "mitre_technique_id": "T1046",
        "confidence_score": 0.95,
        "severity": "LOW",
        "raw_telemetry_summary": "Normal scheduled container healthcheck traffic."
    }
    benign_alert = NIDSAlert.model_validate(benign_dict)

    good_noop = {
        "threat_classification": "BENIGN",
        "severity": "LOW",
        "reasoning_trace": "Traffic matches normal HTTP healthcheck profile. No firewall intervention needed.",
        "chosen_mitigation": {
            "action_type": "NO_OP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "# NO_OP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "MODERATE"
        },
        "rejection_reason": "Blocking pc-2 during benign healthchecks breaks legitimate inter-service monitoring."
    }

    rep_good = validate_and_score_mitigation(benign_alert, good_noop)
    assert rep_good.is_valid is True
    assert rep_good.reward_breakdown.total_reward == 8.0

    # Now test false-positive blocking of benign traffic
    bad_block = dict(good_noop)
    bad_block["chosen_mitigation"] = good_noop["rejected_alternative"]
    bad_block["rejected_alternative"] = good_noop["chosen_mitigation"]

    rep_bad = validate_and_score_mitigation(benign_alert, bad_block)
    assert rep_bad.is_valid is False
    assert rep_bad.reward_breakdown.surgical_precision_score < 0.0


def test_shell_injection_and_malformed_json_penalties(synthetic_syn_flood_alert):
    """Ensures shell metacharacters and broken JSON strings are caught and heavily penalized."""
    malformed_report = validate_and_score_mitigation(synthetic_syn_flood_alert, "{not_valid_json")
    assert malformed_report.is_valid is False
    assert malformed_report.reward_breakdown.schema_compliance_score == -2.0
    assert malformed_report.reward_breakdown.total_reward == -8.0

    injection_envelope = {
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "Injecting shell command.",
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -j DROP && rm -rf /",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "ISOLATE_NODE",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -P INPUT DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Too broad."
    }
    inj_report = validate_and_score_mitigation(synthetic_syn_flood_alert, injection_envelope)
    assert inj_report.is_valid is False
    assert any("forbidden shell metacharacters" in e for e in inj_report.errors)


def test_unsloth_grpo_reward_wrapper_batch(synthetic_syn_flood_alert):
    """Verifies Shaurya's Unsloth GRPOTrainer batch reward function interface."""
    alert_json = synthetic_syn_flood_alert.model_dump_json()
    good_completion = json.dumps({
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "Surgical block of SYN flood source IP.",
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "ISOLATE_NODE",
            "target_container": "pc-3",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -P INPUT DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Isolating pc-3 drops traffic from all healthy containers."
    })
    bad_completion = "invalid json output"

    rewards = grpo_total_reward_func(
        prompts=["prompt1", "prompt2"],
        completions=[good_completion, bad_completion],
        nids_alerts=[alert_json, alert_json],
    )
    assert rewards == [8.0, -8.0]