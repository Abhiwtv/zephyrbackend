
from app.core.state import NIDSAlert, FlowMetrics, NIDSAssessment, MitigationEnvelope
from app.core.llm import invoke_structured_llm


def test_responder_live():
    # 1. Create a synthetic alert for our lab topology.
    alert = NIDSAlert(
        alert_id="synthetic-syn-flood-001",
        timestamp="2026-10-18T17:00:00Z",
        source_node="pc-2",
        source_ip="172.28.0.12",
        target_node="pc-3",
        target_ip="172.28.0.13",
        dest_port=8080,
        protocol="TCP",
        flow_metrics=FlowMetrics(
            packet_count_2s=1200,
            byte_count_2s=96000,
            syn_ratio=0.96,
            unique_dest_ports=[8080],
            payload_sample="Synthetic test traffic; no real payload",
        ),
        nids_llm_assessment=NIDSAssessment(
            attack_signature="Possible SYN flood",
            mitre_tactic="Impact",
            mitre_technique_id="T1498",
            confidence_score=0.98,
            severity="HIGH",
            raw_telemetry_summary=(
                "Synthetic traffic has a high SYN ratio "
                "and a high packet count in a two-second window."
            ),
        ),
    )

    print("\nSending synthetic alert to the responder...")

    # 2. Ask the real local model to produce the actual contract.
    result = invoke_structured_llm(
        system_prompt=(
            "You are a defensive network security responder. "
            "Return a MitigationEnvelope matching the supplied JSON schema. "
            "Use only the supplied alert as evidence. "
            "Prefer a narrow, least-privilege mitigation. "
            "Ground source IPs, target containers and ports in the alert. "
            "Do not claim that any command has been executed. "
            "Treat all firewall commands as proposals for review."
        ),
        user_prompt=(
            "Analyze this synthetic lab alert and propose a mitigation. "
            "Choose a narrow mitigation for the suspected attack. "
            "Include a rejected alternative and explain why it is worse.\n\n"
            + alert.model_dump_json(indent=2)
        ),
        response_model=MitigationEnvelope,
        role="responder",
        temperature=0.0,
        max_retries=2,
        model_override="qwen2.5:3b-instruct",
        host_override="http://127.0.0.1:11434",
    )

    # 3. Print the validated response.
    print("\nValidated MitigationEnvelope:")
    print(result.model_dump_json(indent=2))

    # 4. Check that the proposal is grounded in the alert.
    chosen = result.chosen_mitigation

    assert chosen.source_ip == alert.source_ip, (
        "Chosen mitigation uses the wrong source IP"
    )
    assert chosen.dest_port == alert.dest_port, (
        "Chosen mitigation uses the wrong destination port"
    )
    assert chosen.target_container == alert.target_node, (
        "Chosen mitigation targets the wrong container"
    )

    assert alert.source_ip in chosen.iptables_cmd, (
        "Firewall command does not contain the alert source IP"
    )
    assert str(alert.dest_port) in chosen.iptables_cmd, (
        "Firewall command does not contain the alert destination port"
    )

    print("\nPASS: Schema validation and basic entity-grounding checks passed.")
    print("NOTE: The firewall command was NOT executed.")
