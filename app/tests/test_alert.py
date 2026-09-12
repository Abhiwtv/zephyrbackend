import pytest
from app.tools.mock_env import (
    simulate_blast_radius,
    check_vulnerability,
    execute_firewall_change,
    verify_network_traffic
)

def test_blast_radius_fatal_cdn_trap():
    """Verify the mock environment catches CDN/Gateway collateral damage."""
    result = simulate_blast_radius.invoke({
        "action": "BLOCK_SOURCE",
        "target": "104.28.15.12"  # Mocked Cloudflare CDN Edge
    })
    assert "[FATAL]" in result
    assert "Cloudflare" in result

def test_blast_radius_safe_internal_isolation():
    """Verify isolating internal victims passes the review guardrail."""
    result = simulate_blast_radius.invoke({
        "action": "ISOLATE_ASSET",
        "target": "10.0.1.15"  # Mocked Internal App Server
    })
    assert "[SAFE]" in result
    assert "VLAN" in result

def test_check_vulnerability_tool():
    """Verify mocked host vulnerability scanner tool."""
    vuln_res = check_vulnerability.invoke({"ip": "10.0.1.15"})
    assert "CVE-2021-44228" in vuln_res

    clean_res = check_vulnerability.invoke({"ip": "10.0.99.99"})
    assert "No known critical vulnerabilities" in clean_res

def test_execution_and_verification():
    """Verify execution and post-action verification flow."""
    exec_res = execute_firewall_change.invoke({
        "action": "ISOLATE_ASSET",
        "target": "10.0.1.15"
    })
    assert "[SUCCESS]" in exec_res

    verif_res = verify_network_traffic.invoke({"target": "10.0.1.15"})
    assert "[VERIFIED]" in verif_res

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main(["-v", "-s", __file__]))