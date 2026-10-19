import json
from unittest.mock import patch, MagicMock
import pytest

from app.core.llm import (
    get_endpoint_config,
    get_llm,
    get_responder_llm,
    get_sensor_llm,
    extract_json_payload,
    invoke_structured_llm,
    local_llm,
    creative_llm,
)
from app.core.state import MitigationEnvelope, NIDSAlert


def test_default_dual_port_topology_config(monkeypatch):
    """Verifies default ports and models match Master Spec Section 2 & 3."""
    monkeypatch.delenv("RESPONDER_OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESPONDER_MODEL", raising=False)
    monkeypatch.delenv("SENSOR_OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SENSOR_MODEL", raising=False)

    resp_cfg = get_endpoint_config("responder")
    assert resp_cfg["host"] == "http://127.0.0.1:11434"
    assert resp_cfg["base_url"] == "http://127.0.0.1:11434/v1"
    assert resp_cfg["model"] == "zephyr-dpo-v3"

    sensor_cfg = get_endpoint_config("sensor")
    assert sensor_cfg["host"] == "http://127.0.0.1:11435"
    assert sensor_cfg["base_url"] == "http://127.0.0.1:11435/v1"
    assert sensor_cfg["model"] == "qwen2.5-coder:7b-instruct"


def test_env_variable_overrides(monkeypatch):
    """Ensures Shaurya/Shivam can switch to base Qwen2.5-7B via env vars."""
    monkeypatch.setenv("RESPONDER_MODEL", "qwen2.5:7b-instruct")
    monkeypatch.setenv("RESPONDER_OLLAMA_HOST", "http://localhost:11434/")

    resp_cfg = get_endpoint_config("responder")
    assert resp_cfg["model"] == "qwen2.5:7b-instruct"
    assert resp_cfg["host"] == "http://localhost:11434"

    llm_client = get_responder_llm(temperature=0.0)
    assert llm_client.model_name == "qwen2.5:7b-instruct"


def test_backward_compatible_singletons():
    """Ensures existing LangGraph nodes importing local_llm and creative_llm do not break."""
    assert local_llm is not None
    assert creative_llm is not None
    sensor_client = get_sensor_llm()
    assert "11435" in str(sensor_client.openai_api_base)


def test_extract_json_payload_variants():
    """Tests JSON extraction from clean strings, markdown blocks, and <think> tags."""
    raw_clean = '{"key": "value"}'
    assert json.loads(extract_json_payload(raw_clean)) == {"key": "value"}

    raw_markdown = "Here is the mitigation:\n```json\n{\"key\": \"from_fence\"}\n```\nDone."
    assert json.loads(extract_json_payload(raw_markdown)) == {"key": "from_fence"}

    raw_think = "<think>\nAnalyzing packet flow on br-zephyr...\n</think>\n{\"key\": \"after_think\"}"
    assert json.loads(extract_json_payload(raw_think)) == {"key": "after_think"}


@patch("app.core.llm.requests.post")
def test_invoke_structured_llm_responder_mitigation_envelope(mock_post):
    """Verifies Pydantic-constrained decoding sends schema in `format` and returns MitigationEnvelope."""
    valid_envelope = {
        "threat_classification": "SYN_FLOOD",
        "severity": "HIGH",
        "reasoning_trace": "High SYN ratio (0.95) from pc-2 to pc-4 port 80. Applying surgical SYN rate-limit.",
        "chosen_mitigation": {
            "action_type": "RATE_LIMIT_SYN",
            "target_container": "pc-4",
            "source_ip": "172.28.0.12",
            "dest_port": 80,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.12 -p tcp --syn --dport 80 -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "ISOLATE_NODE",
            "target_container": "pc-4",
            "source_ip": "172.28.0.12",
            "dest_port": 80,
            "iptables_cmd": "iptables -P INPUT DROP",
            "estimated_collateral_impact": "HIGH"
        },
        "rejection_reason": "Full container isolation drops all legitimate web traffic to pc-4."
    }

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "message": {"content": json.dumps(valid_envelope)}
    }
    mock_post.return_value = mock_resp

    result = invoke_structured_llm(
        system_prompt="You are Zephyr Responder.",
        user_prompt="Mitigate SYN flood.",
        response_model=MitigationEnvelope,
        role="responder",
    )

    assert isinstance(result, MitigationEnvelope)
    assert result.chosen_mitigation.action_type == "RATE_LIMIT_SYN"
    assert result.chosen_mitigation.target_container == "pc-4"

    # Verify Ollama /api/chat payload included Pydantic JSON schema
    called_url = mock_post.call_args[0][0]
    called_payload = mock_post.call_args[1]["json"]
    assert called_url == "http://127.0.0.1:11434/api/chat"
    assert "properties" in called_payload["format"]
    assert "chosen_mitigation" in called_payload["format"]["properties"]


@patch("app.core.llm.requests.post")
def test_invoke_structured_llm_self_repair_on_retry(mock_post):
    """Verifies that if Attempt 1 returns invalid schema data, Attempt 2 self-repairs and succeeds."""
    invalid_envelope = {"threat_classification": "INVALID_ENUM_VALUE"}
    valid_envelope = {
        "threat_classification": "BENIGN",
        "severity": "LOW",
        "reasoning_trace": "Normal HTTP traffic spike; no malicious payload.",
        "chosen_mitigation": {
            "action_type": "NO_OP",
            "target_container": "pc-1",
            "source_ip": "172.28.0.15",
            "dest_port": 443,
            "iptables_cmd": "# NO_OP",
            "estimated_collateral_impact": "ZERO"
        },
        "rejected_alternative": {
            "action_type": "BLOCK_SOURCE_IP",
            "target_container": "pc-1",
            "source_ip": "172.28.0.15",
            "dest_port": 443,
            "iptables_cmd": "iptables -A INPUT -s 172.28.0.15 -p tcp --dport 443 -j DROP",
            "estimated_collateral_impact": "MODERATE"
        },
        "rejection_reason": "Blocking benign traffic from pc-5 causes unnecessary service disruption."
    }

    resp_fail = MagicMock()
    resp_fail.raise_for_status.return_value = None
    resp_fail.json.return_value = {"message": {"content": json.dumps(invalid_envelope)}}

    resp_ok = MagicMock()
    resp_ok.raise_for_status.return_value = None
    resp_ok.json.return_value = {"message": {"content": json.dumps(valid_envelope)}}

    mock_post.side_effect = [resp_fail, resp_ok]

    result = invoke_structured_llm(
        system_prompt="System prompt",
        user_prompt="User prompt",
        response_model=MitigationEnvelope,
        role="responder",
        max_retries=2,
    )

    assert mock_post.call_count == 2
    assert result.threat_classification == "BENIGN"
    assert result.chosen_mitigation.action_type == "NO_OP"