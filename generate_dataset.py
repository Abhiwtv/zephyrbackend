"""Project Zephyr - NIDSAlert Dataset Generator.

Generates synthetic Contract A NIDS alerts and sidecar ground truth labels
modelled on CIC-IDS2017 and CSE-CIC-IDS2018 benchmark schedules for a 5-node LAN.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import random
import re
import sys
import uuid
from collections import Counter
from typing import Any, Dict, List, Literal, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ==============================================================================
# Contract A & Sidecar Pydantic Models (Strict, Extra Forbidden)
# ==============================================================================

NODE_IP_MAP = {
    "pc-1": "172.28.0.11",
    "pc-2": "172.28.0.12",
    "pc-3": "172.28.0.13",
    "pc-4": "172.28.0.14",
    "pc-5": "172.28.0.15",
}


class FlowMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packet_count_2s: int = Field(..., ge=1)
    byte_count_2s: int = Field(..., ge=64)
    syn_ratio: float = Field(..., ge=0.0, le=1.0)
    unique_dest_ports: List[int] = Field(...)
    payload_sample: str = Field(..., max_length=160)

    @field_validator("unique_dest_ports")
    @classmethod
    def validate_unique_dest_ports(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("unique_dest_ports cannot be empty")
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} outside valid range 1-65535")
        if v != sorted(set(v)):
            raise ValueError("unique_dest_ports must be unique and sorted in ascending order")
        return v

    @model_validator(mode="after")
    def validate_byte_packet_ratio(self) -> "FlowMetrics":
        if self.byte_count_2s < 54 * self.packet_count_2s:
            raise ValueError(
                f"byte_count_2s ({self.byte_count_2s}) must be >= 54 * packet_count_2s ({54 * self.packet_count_2s})"
            )
        return self


class NidsLlmAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_signature: str = Field(..., min_length=1)
    mitre_tactic: str = Field(..., min_length=1)
    mitre_technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    raw_telemetry_summary: str = Field(..., min_length=1)


class NIDSAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(...)
    timestamp: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    source_node: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    target_node: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    source_ip: Literal["172.28.0.11", "172.28.0.12", "172.28.0.13", "172.28.0.14", "172.28.0.15"]
    target_ip: Literal["172.28.0.11", "172.28.0.12", "172.28.0.13", "172.28.0.14", "172.28.0.15"]
    dest_port: int = Field(..., ge=1, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "HTTP"]
    flow_metrics: FlowMetrics
    nids_llm_assessment: NidsLlmAssessment

    @model_validator(mode="after")
    def validate_contract_a_rules(self) -> "NIDSAlert":
        # IP matches node
        if self.source_ip != NODE_IP_MAP.get(self.source_node):
            raise ValueError(f"source_ip {self.source_ip} does not match {self.source_node}")
        if self.target_ip != NODE_IP_MAP.get(self.target_node):
            raise ValueError(f"target_ip {self.target_ip} does not match {self.target_node}")

        # source_node != target_node
        if self.source_node == self.target_node:
            raise ValueError(f"source_node ({self.source_node}) cannot equal target_node ({self.target_node})")

        # dest_port inside unique_dest_ports
        if self.dest_port not in self.flow_metrics.unique_dest_ports:
            raise ValueError(f"dest_port {self.dest_port} not in unique_dest_ports {self.flow_metrics.unique_dest_ports}")

        # Scan check: if multiple ports, dest_port must be lowest port
        if len(self.flow_metrics.unique_dest_ports) > 1:
            if self.dest_port != self.flow_metrics.unique_dest_ports[0]:
                raise ValueError(
                    f"Scan dest_port ({self.dest_port}) must be lowest port ({self.flow_metrics.unique_dest_ports[0]})"
                )

        # Benign rules
        if self.nids_llm_assessment.mitre_tactic == "None" or self.nids_llm_assessment.mitre_technique_id == "T0000":
            if self.nids_llm_assessment.severity != "LOW":
                raise ValueError("Benign severity must always be LOW")
            if self.nids_llm_assessment.mitre_tactic != "None" or self.nids_llm_assessment.mitre_technique_id != "T0000":
                raise ValueError("Benign alerts must have mitre_tactic='None' and mitre_technique_id='T0000'")

        # raw_telemetry_summary must quote real numbers
        summary = self.nids_llm_assessment.raw_telemetry_summary
        pkt_str = str(self.flow_metrics.packet_count_2s)
        byte_str = str(self.flow_metrics.byte_count_2s)
        syn_str = f"{self.flow_metrics.syn_ratio:.2f}"
        syn_str_exact = str(self.flow_metrics.syn_ratio)
        port_str = str(self.dest_port)

        if pkt_str not in summary:
            raise ValueError(f"Summary does not quote packet_count_2s: {pkt_str}")
        if byte_str not in summary:
            raise ValueError(f"Summary does not quote byte_count_2s: {byte_str}")
        if syn_str not in summary and syn_str_exact not in summary:
            raise ValueError(f"Summary does not quote syn_ratio: {syn_str}")
        if port_str not in summary:
            raise ValueError(f"Summary does not quote dest_port: {port_str}")

        return self


class NIDSAlertLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    true_class: Literal["SYN_FLOOD", "RCE_ATTEMPT", "SQL_INJECTION", "SSH_BRUTE_FORCE", "PORT_SCAN", "BENIGN"]
    enum_fit: Literal["exact", "approximate"]
    acceptable_actions: List[str]
    expected_noop: bool
    hard_negative: bool
    source_dataset: str
    original_attack_label: str
    original_src_ip: str
    original_dst_ip: str
    original_timestamp_local: str
    scenario_id: str


# ==============================================================================
# Dataset Generation Logic
# ==============================================================================

def make_uuid4(rng: random.Random) -> str:
    """Generate deterministic UUIDv4 from custom Random instance."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def build_scenario_instances(rng: random.Random) -> List[Dict[str, Any]]:
    """Build the exact 100 scenario definitions with metadata and traffic characteristics."""
    scenarios: List[Dict[str, Any]] = []

    def add(
        count: int,
        scenario_base: str,
        source_dataset: str,
        original_label: str,
        src_node: str,
        dst_node: str,
        dest_ports: List[int],
        protocol: str,
        pkt_range: Tuple[int, int],
        byte_mult_range: Tuple[int, int],
        syn_ratio_range: Tuple[float, float],
        payload_fn: Any,
        attack_sig: str,
        mitre_tactic: str,
        mitre_tech: str,
        severity: str,
        true_class: str,
        enum_fit: str,
        acceptable_actions: List[str],
        expected_noop: bool,
        orig_src_ip: str,
        orig_dst_ip: str,
        time_base: datetime.datetime,
        desc_template: str,
        hard_negative: bool = False,
        ambiguous_indices: List[int] = None,
        multi_src_rotation: bool = False,
    ):
        if ambiguous_indices is None:
            ambiguous_indices = []

        multi_nodes = ["pc-1", "pc-2", "pc-3", "pc-5"]

        for i in range(count):
            sc_id = f"{scenario_base}_{i+1:02d}"
            is_ambiguous = i in ambiguous_indices

            if is_ambiguous:
                conf = round(rng.uniform(0.58, 0.74), 4)
            else:
                conf = round(rng.uniform(0.86, 0.98), 4)

            cur_src = multi_nodes[i % len(multi_nodes)] if multi_src_rotation else src_node
            cur_dst = dst_node

            pkts = rng.randint(pkt_range[0], pkt_range[1])
            byte_mult = rng.randint(byte_mult_range[0], byte_mult_range[1])
            bytes_2s = max(64, max(54 * pkts, pkts * byte_mult))
            syn_r = round(rng.uniform(syn_ratio_range[0], syn_ratio_range[1]), 2)
            ports = sorted(list(set(dest_ports)))
            primary_port = ports[0]
            payload = payload_fn(i)

            # Local timestamp offset within scenario window
            sec_offset = i * 180 + rng.randint(0, 59)
            local_dt = time_base + datetime.timedelta(seconds=sec_offset)
            local_ts_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")
            utc_ts_str = local_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            ports_desc = f"ports {ports}" if len(ports) > 1 else f"dest_port {primary_port}"
            summary = (
                f"Observed {pkts} packets ({bytes_2s} bytes) over 2s with syn_ratio {syn_r:.2f} "
                f"targeting {ports_desc}: {desc_template}"
            )

            # Contract A item
            contract_a = {
                "alert_id": "",  # Filled later deterministically
                "timestamp": utc_ts_str,
                "source_node": cur_src,
                "target_node": cur_dst,
                "source_ip": NODE_IP_MAP[cur_src],
                "target_ip": NODE_IP_MAP[cur_dst],
                "dest_port": primary_port,
                "protocol": protocol,
                "flow_metrics": {
                    "packet_count_2s": pkts,
                    "byte_count_2s": bytes_2s,
                    "syn_ratio": syn_r,
                    "unique_dest_ports": ports,
                    "payload_sample": payload[:160],
                },
                "nids_llm_assessment": {
                    "attack_signature": attack_sig,
                    "mitre_tactic": mitre_tactic,
                    "mitre_technique_id": mitre_tech,
                    "confidence_score": conf,
                    "severity": severity,
                    "raw_telemetry_summary": summary,
                },
            }

            # Sidecar label item
            sidecar = {
                "alert_id": "",
                "true_class": true_class,
                "enum_fit": enum_fit,
                "acceptable_actions": acceptable_actions,
                "expected_noop": expected_noop,
                "hard_negative": hard_negative,
                "source_dataset": source_dataset,
                "original_attack_label": original_label,
                "original_src_ip": orig_src_ip,
                "original_dst_ip": orig_dst_ip,
                "original_timestamp_local": local_ts_str,
                "scenario_id": sc_id,
            }

            scenarios.append({"contract_a": contract_a, "sidecar": sidecar})

    # --------------------------------------------------------------------------
    # 1. CIC-IDS2017 Scenarios (Total: 53)
    # --------------------------------------------------------------------------

    # FTP-Patator (4): Tue 04/07/2017 09:20-10:20
    add(
        count=4,
        scenario_base="cic17_ftp_patator",
        source_dataset="CIC-IDS2017",
        original_label="FTP-Patator",
        src_node="pc-2",
        dst_node="pc-3",
        dest_ports=[21],
        protocol="TCP",
        pkt_range=(45, 120),
        byte_mult_range=(68, 92),
        syn_ratio_range=(0.18, 0.28),
        payload_fn=lambda idx: f"USER admin\r\nPASS password{100+idx}\r\n",
        attack_sig="NIDS: FTP Authentication Brute-Force Activity Detected",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="MEDIUM",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 4, 9, 20, 0),
        desc_template="Rapid sequential FTP login attempts with invalid credentials.",
    )

    # SSH-Patator (4): Tue 04/07/2017 14:00-15:00
    add(
        count=4,
        scenario_base="cic17_ssh_patator",
        source_dataset="CIC-IDS2017",
        original_label="SSH-Patator",
        src_node="pc-2",
        dst_node="pc-3",
        dest_ports=[22],
        protocol="TCP",
        pkt_range=(60, 180),
        byte_mult_range=(85, 140),
        syn_ratio_range=(0.12, 0.22),
        payload_fn=lambda idx: "SSH-2.0-paramiko_2.1.2\r\n",
        attack_sig="NIDS: SSH Authentication Brute-Force (SSH-Patator)",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="HIGH",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="exact",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 4, 14, 0, 0),
        desc_template="SSH password spraying from automated paramiko script.",
    )

    # DoS Slowloris (3): Wed 05/07/2017 09:47-10:10 (1 ambiguous)
    add(
        count=3,
        scenario_base="cic17_slowloris",
        source_dataset="CIC-IDS2017",
        original_label="DoS Slowloris",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(120, 260),
        byte_mult_range=(58, 80),
        syn_ratio_range=(0.04, 0.08),
        payload_fn=lambda idx: "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nX-a: b\r\n",
        attack_sig="NIDS: DoS Slowloris Incomplete HTTP Header Exhaustion",
        mitre_tactic="Impact",
        mitre_tech="T1499.003",
        severity="HIGH",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 5, 9, 47, 0),
        desc_template="Persistent slow HTTP connections holding server threads open.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # DoS Slowhttptest (3): Wed 05/07/2017 10:14-10:35 (1 ambiguous)
    add(
        count=3,
        scenario_base="cic17_slowhttptest",
        source_dataset="CIC-IDS2017",
        original_label="DoS Slowhttptest",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="TCP",
        pkt_range=(150, 320),
        byte_mult_range=(62, 90),
        syn_ratio_range=(0.03, 0.07),
        payload_fn=lambda idx: "POST /login HTTP/1.1\r\nContent-Length: 10000\r\n",
        attack_sig="NIDS: DoS Slowhttptest Slow Read/Write Starvation",
        mitre_tactic="Impact",
        mitre_tech="T1499.003",
        severity="HIGH",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 5, 10, 14, 0),
        desc_template="Low-rate slow POST body transmission starving web server sockets.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # DoS Hulk (3): Wed 05/07/2017 10:43-11:00
    add(
        count=3,
        scenario_base="cic17_hulk",
        source_dataset="CIC-IDS2017",
        original_label="DoS Hulk",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(1800, 3800),
        byte_mult_range=(320, 650),
        syn_ratio_range=(0.02, 0.05),
        payload_fn=lambda idx: f"GET /?cache_buster={91024+idx} HTTP/1.1\r\nHost: 172.28.0.14\r\n",
        attack_sig="NIDS: DoS HULK Unique URL Flooding Pattern",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 5, 10, 43, 0),
        desc_template="High volume obfuscated GET requests bypassing cache.",
    )

    # DoS GoldenEye (3): Wed 05/07/2017 11:10-11:23
    add(
        count=3,
        scenario_base="cic17_goldeneye",
        source_dataset="CIC-IDS2017",
        original_label="DoS GoldenEye",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(1400, 2900),
        byte_mult_range=(380, 720),
        syn_ratio_range=(0.02, 0.06),
        payload_fn=lambda idx: "GET / HTTP/1.1\r\nUser-Agent: GoldenEye\r\nCache-Control: no-cache\r\n",
        attack_sig="NIDS: DoS GoldenEye Layer-7 Web Stress Flood",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 5, 11, 10, 0),
        desc_template="Keep-alive cache evasion HTTP request barrage.",
    )

    # Heartbleed (3): Wed 05/07/2017 15:12-15:32 (port 444, pc-2 -> pc-3)
    add(
        count=3,
        scenario_base="cic17_heartbleed",
        source_dataset="CIC-IDS2017",
        original_label="Heartbleed",
        src_node="pc-2",
        dst_node="pc-3",
        dest_ports=[444],
        protocol="TCP",
        pkt_range=(48, 95),
        byte_mult_range=(160, 420),
        syn_ratio_range=(0.05, 0.12),
        payload_fn=lambda idx: "\\x18\\x03\\x02\\x00\\x03\\x01\\x40\\x00",
        attack_sig="NIDS: OpenSSL TLS Heartbeat Memory Disclosure (CVE-2014-0160)",
        mitre_tactic="Credential Access",
        mitre_tech="T1190",
        severity="CRITICAL",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.51",
        time_base=datetime.datetime(2017, 7, 5, 15, 12, 0),
        desc_template="Malformed TLS heartbeat request with length mismatch leaking process memory.",
    )

    # Web brute force (3): Thu 06/07/2017 09:20-10:00
    add(
        count=3,
        scenario_base="cic17_web_bf",
        source_dataset="CIC-IDS2017",
        original_label="Web Attack - Brute Force",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(50, 160),
        byte_mult_range=(210, 380),
        syn_ratio_range=(0.10, 0.20),
        payload_fn=lambda idx: f"POST /dvwa/login.php HTTP/1.1\r\nusername=admin&password=guess{idx}\r\n",
        attack_sig="NIDS: Web Application Credential Brute-Force",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="MEDIUM",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 6, 9, 20, 0),
        desc_template="Burp Suite/Hydra automated POST requests to web login endpoint.",
    )

    # XSS (3): Thu 06/07/2017 10:15-10:35
    add(
        count=3,
        scenario_base="cic17_xss",
        source_dataset="CIC-IDS2017",
        original_label="Web Attack - XSS",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(35, 80),
        byte_mult_range=(280, 480),
        syn_ratio_range=(0.04, 0.10),
        payload_fn=lambda idx: "GET /vulnerabilities/xss_r/?name=<script>alert('xss')</script> HTTP/1.1\r\n",
        attack_sig="NIDS: Reflected Cross-Site Scripting (XSS) Pattern in URI",
        mitre_tactic="Execution",
        mitre_tech="T1059.007",
        severity="HIGH",
        true_class="SQL_INJECTION",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "waf_rule_update"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 6, 10, 15, 0),
        desc_template="Suspicious script tags and JavaScript execution hooks detected in GET parameter.",
    )

    # SQLi (3): Thu 06/07/2017 10:40-10:42
    add(
        count=3,
        scenario_base="cic17_sqli",
        source_dataset="CIC-IDS2017",
        original_label="Web Attack - Sql Injection",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(40, 95),
        byte_mult_range=(320, 560),
        syn_ratio_range=(0.04, 0.09),
        payload_fn=lambda idx: "GET /item.php?id=1' UNION SELECT 1,table_name,3 FROM information_schema.tables-- HTTP/1.1\r\n",
        attack_sig="NIDS: SQL Injection Signature Detected (UNION SELECT / Tautology)",
        mitre_tactic="Initial Access",
        mitre_tech="T1190",
        severity="CRITICAL",
        true_class="SQL_INJECTION",
        enum_fit="exact",
        acceptable_actions=["block_ip", "waf_rule_update"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 6, 10, 40, 0),
        desc_template="SQL meta-characters and schema inspection clauses in HTTP request query.",
    )

    # Infiltration Vista (3): Thu 06/07/2017 14:19-15:45 (1 ambiguous)
    add(
        count=3,
        scenario_base="cic17_infil_vista",
        source_dataset="CIC-IDS2017",
        original_label="Infiltration",
        src_node="pc-2",
        dst_node="pc-1",
        dest_ports=[445],
        protocol="TCP",
        pkt_range=(85, 210),
        byte_mult_range=(180, 450),
        syn_ratio_range=(0.08, 0.16),
        payload_fn=lambda idx: "\\xffSMBu\\x00\\x00\\x00\\x00psexecsvc.exe\\x00",
        attack_sig="NIDS: Remote Service Execution via SMB/PsExec (Infiltration)",
        mitre_tactic="Initial Access",
        mitre_tech="T1210",
        severity="HIGH",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.8",
        time_base=datetime.datetime(2017, 7, 6, 14, 19, 0),
        desc_template="Malicious binary staging and execution over SMB named pipe on Windows client.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # Infiltration Cool-disk MAC (2): Thu 06/07/2017 15:00-15:40 (1 ambiguous)
    add(
        count=2,
        scenario_base="cic17_infil_mac",
        source_dataset="CIC-IDS2017",
        original_label="Infiltration",
        src_node="pc-2",
        dst_node="pc-5",
        dest_ports=[88],
        protocol="TCP",
        pkt_range=(70, 160),
        byte_mult_range=(200, 410),
        syn_ratio_range=(0.06, 0.14),
        payload_fn=lambda idx: "KRB5_AS_REQ kerberos staging payload mac\\x00",
        attack_sig="NIDS: Lateral Movement Attempt via Staged Kerberos Ticket",
        mitre_tactic="Lateral Movement",
        mitre_tech="T1091",
        severity="HIGH",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.25",
        time_base=datetime.datetime(2017, 7, 6, 15, 0, 0),
        desc_template="Kerberos ticket forging attempt targeting domain controller / secondary host.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # Infiltration portscan from Vista (pc-1 source) (3): Thu 06/07/2017 15:46-17:00
    infil_scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080
    ]
    add(
        count=3,
        scenario_base="cic17_infil_scan_vista",
        source_dataset="CIC-IDS2017",
        original_label="PortScan",
        src_node="pc-1",
        dst_node="pc-3",
        dest_ports=infil_scan_ports,
        protocol="TCP",
        pkt_range=(350, 750),
        byte_mult_range=(54, 60),
        syn_ratio_range=(0.92, 0.99),
        payload_fn=lambda idx: "",
        attack_sig="NIDS: Internal Reconnaissance Port Scan from Compromised Host",
        mitre_tactic="Discovery",
        mitre_tech="T1046",
        severity="HIGH",
        true_class="PORT_SCAN",
        enum_fit="exact",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.51",
        time_base=datetime.datetime(2017, 7, 6, 15, 46, 0),
        desc_template="Compromised internal workstation probing core subnet infrastructure ports.",
    )

    # Botnet ARES (pc-1 -> pc-2 C2) (3): Fri 07/07/2017 09:00-10:00 (1 ambiguous)
    add(
        count=3,
        scenario_base="cic17_botnet_ares",
        source_dataset="CIC-IDS2017",
        original_label="Bot",
        src_node="pc-1",
        dst_node="pc-2",
        dest_ports=[8080],
        protocol="HTTP",
        pkt_range=(55, 140),
        byte_mult_range=(240, 460),
        syn_ratio_range=(0.04, 0.09),
        payload_fn=lambda idx: f"POST /api/v1/beacon HTTP/1.1\r\nHost: 172.28.0.12\r\nAgentId=win-vista-{idx}&status=ready\r\n",
        attack_sig="NIDS: ARES Botnet Command & Control (C2) Heartbeat Beacon",
        mitre_tactic="Command and Control",
        mitre_tech="T1071.001",
        severity="HIGH",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="205.174.165.73",
        time_base=datetime.datetime(2017, 7, 7, 9, 0, 0),
        desc_template="Periodic structured HTTP POST beacons to known external C2 server.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # Port scan nmap variants (sS, sT, sF, sX, sN, sU) (6): Fri 07/07/2017 13:58-15:00 (sN ambiguous)
    tcp_scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]
    udp_scan_ports = [
        53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353
    ]
    scan_configs = [
        ("sS", "TCP", tcp_scan_ports, (0.92, 0.99), lambda: "", "Nmap TCP SYN Stealth Scan (sS)", False),
        ("sT", "TCP", tcp_scan_ports, (0.35, 0.45), lambda: "", "Nmap Full TCP Connect Scan (sT)", False),
        ("sF", "TCP", tcp_scan_ports, (0.00, 0.00), lambda: "", "Nmap TCP FIN Stealth Probe (sF)", False),
        ("sX", "TCP", tcp_scan_ports, (0.00, 0.00), lambda: "", "Nmap TCP Xmas Tree Probe (sX - FIN/PSH/URG)", False),
        ("sN", "TCP", tcp_scan_ports, (0.00, 0.00), lambda: "", "Nmap TCP Null Probe (sN - No Flags)", True),
        ("sU", "UDP", udp_scan_ports, (0.00, 0.00), lambda: "", "Nmap UDP Service Discovery Scan (sU)", False),
    ]

    for idx, (variant, proto, ports, syn_rng, pld_fn, sig_name, is_ambig) in enumerate(scan_configs):
        add(
            count=1,
            scenario_base=f"cic17_nmap_{variant.lower()}",
            source_dataset="CIC-IDS2017",
            original_label="PortScan",
            src_node="pc-2",
            dst_node="pc-4",
            dest_ports=ports,
            protocol=proto,
            pkt_range=(180, 450),
            byte_mult_range=(54, 70),
            syn_ratio_range=syn_rng,
            payload_fn=lambda i: pld_fn(),
            attack_sig=f"NIDS: {sig_name}",
            mitre_tactic="Discovery",
            mitre_tech="T1046",
            severity="MEDIUM",
            true_class="PORT_SCAN",
            enum_fit="exact",
            acceptable_actions=["block_ip", "rate_limit"],
            expected_noop=False,
            orig_src_ip="205.174.165.73",
            orig_dst_ip="192.168.10.50",
            time_base=datetime.datetime(2017, 7, 7, 13, 58, 0) + datetime.timedelta(minutes=idx * 8),
            desc_template=f"Nmap scanner profiling destination ports using {variant} signature.",
            ambiguous_indices=[0] if is_ambig else [],
        )

    # DDoS LOIT (4): Fri 07/07/2017 15:56-16:16 (Multi-source rotated)
    add(
        count=4,
        scenario_base="cic17_ddos_loit",
        source_dataset="CIC-IDS2017",
        original_label="DDoS",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="TCP",
        pkt_range=(3500, 8000),
        byte_mult_range=(54, 62),
        syn_ratio_range=(0.88, 0.98),
        payload_fn=lambda idx: "",
        attack_sig="NIDS: Distributed SYN Flood Attack (LOIT)",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="205.174.165.73",
        orig_dst_ip="192.168.10.50",
        time_base=datetime.datetime(2017, 7, 7, 15, 56, 0),
        desc_template="Massive synchronized TCP SYN packet flood overwhelming network backlog.",
        multi_src_rotation=True,
    )

    # --------------------------------------------------------------------------
    # 2. CSE-CIC-IDS2018 Scenarios (Total: 32)
    # --------------------------------------------------------------------------

    # FTP-BF (2): Wed 14/02/2018
    add(
        count=2,
        scenario_base="cic18_ftp_bf",
        source_dataset="CSE-CIC-IDS2018",
        original_label="FTP-BruteForce",
        src_node="pc-2",
        dst_node="pc-3",
        dest_ports=[21],
        protocol="TCP",
        pkt_range=(50, 110),
        byte_mult_range=(68, 88),
        syn_ratio_range=(0.18, 0.26),
        payload_fn=lambda idx: f"USER root\r\nPASS toor{idx}\r\n",
        attack_sig="NIDS: High-Frequency FTP Credential Guessing (2018)",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="MEDIUM",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 14, 9, 30, 0),
        desc_template="Continuous dictionary attacks against FTP authentication daemon.",
    )

    # SSH-BF (2): Wed 14/02/2018
    add(
        count=2,
        scenario_base="cic18_ssh_bf",
        source_dataset="CSE-CIC-IDS2018",
        original_label="SSH-BruteForce",
        src_node="pc-2",
        dst_node="pc-3",
        dest_ports=[22],
        protocol="TCP",
        pkt_range=(70, 160),
        byte_mult_range=(90, 130),
        syn_ratio_range=(0.14, 0.22),
        payload_fn=lambda idx: "SSH-2.0-libssh2_1.8.0\r\n",
        attack_sig="NIDS: Automated SSH Key/Password Exchange Brute-Force",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="HIGH",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="exact",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 14, 14, 15, 0),
        desc_template="Rapid SSH protocol key renegotiations indicating automated brute-force.",
    )

    # GoldenEye (2): Thu 15/02/2018
    add(
        count=2,
        scenario_base="cic18_goldeneye",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DoS-GoldenEye",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(1600, 3200),
        byte_mult_range=(390, 680),
        syn_ratio_range=(0.02, 0.05),
        payload_fn=lambda idx: "GET / HTTP/1.1\r\nUser-Agent: GoldenEye\r\nAccept: */*\r\n",
        attack_sig="NIDS: Application DoS GoldenEye HTTP Worker Exhaustion",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 15, 9, 30, 0),
        desc_template="Persistent un-cacheable GET queries saturating web server threads.",
    )

    # Slowloris (2): Thu 15/02/2018
    add(
        count=2,
        scenario_base="cic18_slowloris",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DoS-Slowloris",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="TCP",
        pkt_range=(140, 290),
        byte_mult_range=(60, 85),
        syn_ratio_range=(0.04, 0.08),
        payload_fn=lambda idx: "GET /index.php HTTP/1.1\r\nX-Header: slowloris\r\n",
        attack_sig="NIDS: DoS Slowloris Connection Table Depletion",
        mitre_tactic="Impact",
        mitre_tech="T1499.003",
        severity="HIGH",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 15, 14, 0, 0),
        desc_template="Hanging connection pool starving concurrent client allocations.",
    )

    # SlowHTTPTest (2): Fri 16/02/2018
    add(
        count=2,
        scenario_base="cic18_slowhttptest",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DoS-SlowHTTPTest",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="TCP",
        pkt_range=(160, 310),
        byte_mult_range=(65, 88),
        syn_ratio_range=(0.03, 0.07),
        payload_fn=lambda idx: "POST /contact HTTP/1.1\r\nContent-Length: 40960\r\n",
        attack_sig="NIDS: DoS SlowHTTPTest Slow-POST Bandwidth Throttling",
        mitre_tactic="Impact",
        mitre_tech="T1499.003",
        severity="HIGH",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 16, 10, 15, 0),
        desc_template="Trickling request data stalling application response buffers.",
    )

    # Hulk (2): Fri 16/02/2018
    add(
        count=2,
        scenario_base="cic18_hulk",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DoS-Hulk",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(1900, 3600),
        byte_mult_range=(340, 620),
        syn_ratio_range=(0.02, 0.05),
        payload_fn=lambda idx: f"GET /search?q={idx*7382} HTTP/1.1\r\nHost: 172.28.0.14\r\n",
        attack_sig="NIDS: DoS HULK Web Application Request Flood",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 16, 14, 30, 0),
        desc_template="Dynamic URI generation exhausting web server memory.",
    )

    # LOIC-HTTP (3): Tue 20/02/2018 (Multi-source rotated)
    add(
        count=3,
        scenario_base="cic18_loic_http",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DDoS-LOIC-HTTP",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(2200, 4800),
        byte_mult_range=(250, 490),
        syn_ratio_range=(0.02, 0.06),
        payload_fn=lambda idx: "GET / HTTP/1.1\r\nHost: 172.28.0.14\r\nUser-Agent: LOIC\r\n",
        attack_sig="NIDS: LOIC HTTP Flooding Campaign (DDoS)",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 20, 10, 0, 0),
        desc_template="Distributed LOIC HTTP GET flood flooding port 80 listener.",
        multi_src_rotation=True,
    )

    # LOIC-UDP (3): Tue 20/02/2018 (Multi-source rotated)
    add(
        count=3,
        scenario_base="cic18_loic_udp",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DDoS-LOIC-UDP",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="UDP",
        pkt_range=(2400, 5200),
        byte_mult_range=(120, 300),
        syn_ratio_range=(0.00, 0.00),
        payload_fn=lambda idx: "LOIC_UDP_FLOOD_RANDOM_BYTE_STREAM_PAYLOAD",
        attack_sig="NIDS: High Volume UDP Packet Flood (LOIC-UDP)",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 20, 14, 0, 0),
        desc_template="Stateless high-rate UDP packet flood consuming inbound interface bandwidth.",
        multi_src_rotation=True,
    )

    # HOIC (3): Wed 21/02/2018 (Multi-source rotated)
    add(
        count=3,
        scenario_base="cic18_hoic",
        source_dataset="CSE-CIC-IDS2018",
        original_label="DDoS-HOIC",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(2500, 5600),
        byte_mult_range=(350, 710),
        syn_ratio_range=(0.02, 0.06),
        payload_fn=lambda idx: "GET /index.html HTTP/1.1\r\nHost: 172.28.0.14\r\nUser-Agent: HOIC/2.1\r\n",
        attack_sig="NIDS: High Orbit Ion Cannon (HOIC) Booster Flood",
        mitre_tactic="Impact",
        mitre_tech="T1498.001",
        severity="CRITICAL",
        true_class="SYN_FLOOD",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "rate_limit"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 21, 10, 30, 0),
        desc_template="Multi-threaded randomized HTTP request swarm using HOIC booster scripts.",
        multi_src_rotation=True,
    )

    # Web BF (2): Thu 22/02/2018 (1 ambiguous)
    add(
        count=2,
        scenario_base="cic18_web_bf",
        source_dataset="CSE-CIC-IDS2018",
        original_label="Brute Force -Web",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(45, 140),
        byte_mult_range=(220, 390),
        syn_ratio_range=(0.09, 0.18),
        payload_fn=lambda idx: f"POST /api/auth HTTP/1.1\r\nuser=manager&pwd=pass{idx}\r\n",
        attack_sig="NIDS: Automated Web Portal Password Guessing",
        mitre_tactic="Credential Access",
        mitre_tech="T1110.001",
        severity="MEDIUM",
        true_class="SSH_BRUTE_FORCE",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "reset_credentials"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.28",
        time_base=datetime.datetime(2018, 2, 22, 10, 15, 0),
        desc_template="Burp Intruder credential stuffing pattern against authentication API.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # XSS (2): Thu 22/02/2018
    add(
        count=2,
        scenario_base="cic18_xss",
        source_dataset="CSE-CIC-IDS2018",
        original_label="Brute Force -XSS",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(38, 85),
        byte_mult_range=(290, 510),
        syn_ratio_range=(0.04, 0.09),
        payload_fn=lambda idx: "GET /comment?body=<img src=x onerror=alert(1)> HTTP/1.1\r\n",
        attack_sig="NIDS: Stored/Reflected XSS Vector Injection",
        mitre_tactic="Execution",
        mitre_tech="T1059.007",
        severity="HIGH",
        true_class="SQL_INJECTION",
        enum_fit="approximate",
        acceptable_actions=["block_ip", "waf_rule_update"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.28",
        time_base=datetime.datetime(2018, 2, 22, 14, 0, 0),
        desc_template="HTML event-handler XSS injection attempt in web parameter.",
    )

    # SQLi (2): Fri 23/02/2018
    add(
        count=2,
        scenario_base="cic18_sqli",
        source_dataset="CSE-CIC-IDS2018",
        original_label="SQL Injection",
        src_node="pc-2",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(42, 98),
        byte_mult_range=(310, 580),
        syn_ratio_range=(0.04, 0.08),
        payload_fn=lambda idx: "GET /search?id=1 AND 1=CONVERT(int, (SELECT @@version)) HTTP/1.1\r\n",
        attack_sig="NIDS: Error-Based SQL Injection Pattern",
        mitre_tactic="Initial Access",
        mitre_tech="T1190",
        severity="CRITICAL",
        true_class="SQL_INJECTION",
        enum_fit="exact",
        acceptable_actions=["block_ip", "waf_rule_update"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.28",
        time_base=datetime.datetime(2018, 2, 23, 10, 30, 0),
        desc_template="Database syntax extraction and type conversion error exploitation.",
    )

    # Infiltration (3): Wed 28/02/2018 (1 ambiguous)
    add(
        count=3,
        scenario_base="cic18_infil",
        source_dataset="CSE-CIC-IDS2018",
        original_label="Infilteration",
        src_node="pc-2",
        dst_node="pc-1",
        dest_ports=[445],
        protocol="TCP",
        pkt_range=(90, 220),
        byte_mult_range=(190, 460),
        syn_ratio_range=(0.07, 0.15),
        payload_fn=lambda idx: "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        attack_sig="NIDS: Malicious PowerShell Stager Ingress over SMB",
        mitre_tactic="Initial Access",
        mitre_tech="T1189",
        severity="HIGH",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="18.218.115.60",
        orig_dst_ip="172.31.69.25",
        time_base=datetime.datetime(2018, 2, 28, 11, 0, 0),
        desc_template="Encoded PowerShell stager transfer detected traversing Windows SMB pipe.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # Bot (2): Fri 02/03/2018 (1 ambiguous)
    add(
        count=2,
        scenario_base="cic18_bot",
        source_dataset="CSE-CIC-IDS2018",
        original_label="Bot",
        src_node="pc-1",
        dst_node="pc-2",
        dest_ports=[8080],
        protocol="HTTP",
        pkt_range=(60, 150),
        byte_mult_range=(260, 490),
        syn_ratio_range=(0.03, 0.08),
        payload_fn=lambda idx: f"POST /gate.php HTTP/1.1\r\nHost: 172.28.0.12\r\nmid=win10-pc1-{idx}&cmd=ack\r\n",
        attack_sig="NIDS: Ares/Mirai Botnet C2 Checkin Callback",
        mitre_tactic="Command and Control",
        mitre_tech="T1071.001",
        severity="HIGH",
        true_class="RCE_ATTEMPT",
        enum_fit="approximate",
        acceptable_actions=["isolate_host", "block_ip"],
        expected_noop=False,
        orig_src_ip="172.31.69.25",
        orig_dst_ip="18.218.115.60",
        time_base=datetime.datetime(2018, 3, 2, 10, 0, 0),
        desc_template="Botnet agent checkin beacon with encoded telemetry headers.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # --------------------------------------------------------------------------
    # 3. Benign Scenarios (Total: 15)
    # --------------------------------------------------------------------------
    benign_base_time = datetime.datetime(2017, 7, 3, 9, 0, 0)

    # Web browsing x3 (HTTP): pc-1 -> pc-4
    add(
        count=3,
        scenario_base="benign_http_browse",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(20, 60),
        byte_mult_range=(350, 750),
        syn_ratio_range=(0.03, 0.07),
        payload_fn=lambda idx: "GET /portal/home.html HTTP/1.1\r\nHost: 172.28.0.14\r\nAccept: text/html\r\n",
        attack_sig="NIDS: Normal Intranet HTTP Web Navigation",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.50",
        time_base=benign_base_time + datetime.timedelta(minutes=15),
        desc_template="Standard employee web portal document retrieval.",
    )

    # HTTPS x2: pc-1 -> pc-4
    add(
        count=2,
        scenario_base="benign_https",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-4",
        dest_ports=[443],
        protocol="TCP",
        pkt_range=(25, 75),
        byte_mult_range=(450, 950),
        syn_ratio_range=(0.02, 0.06),
        payload_fn=lambda idx: "\\x16\\x03\\x01\\x00\\xba\\x01\\x00\\x00\\xb6\\x03\\x03ClientHello",
        attack_sig="NIDS: Standard Encrypted HTTPS Session",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.50",
        time_base=benign_base_time + datetime.timedelta(minutes=45),
        desc_template="Legitimate TLS 1.3 handshake and encrypted application data exchange.",
    )

    # DNS x2: pc-1 -> pc-5 (1 ambiguous)
    add(
        count=2,
        scenario_base="benign_dns",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-5",
        dest_ports=[53],
        protocol="UDP",
        pkt_range=(8, 25),
        byte_mult_range=(75, 110),
        syn_ratio_range=(0.00, 0.00),
        payload_fn=lambda idx: "Standard query 0x2b3c A portal.zephyr.lan",
        attack_sig="NIDS: Routine Internal Domain DNS Resolution",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.25",
        time_base=benign_base_time + datetime.timedelta(minutes=75),
        desc_template="Standard recursive DNS lookup to local domain controller.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # rsync backup x1: pc-4 -> pc-3 (bulk transfer, 1 ambiguous)
    add(
        count=1,
        scenario_base="benign_rsync_backup",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-4",
        dst_node="pc-3",
        dest_ports=[873],
        protocol="TCP",
        pkt_range=(1200, 2400),
        byte_mult_range=(1050, 1420),
        syn_ratio_range=(0.001, 0.005),
        payload_fn=lambda idx: "@RSYNCD: 31.0\n",
        attack_sig="NIDS: Scheduled Infrastructure Backup Synchronization",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.50",
        orig_dst_ip="192.168.10.51",
        time_base=benign_base_time + datetime.timedelta(minutes=100),
        desc_template="High volume internal nightly file backup synchronization via rsync daemon.",
        ambiguous_indices=[0],  # 1 ambiguous
    )

    # admin SSH x1: pc-1 -> pc-3
    add(
        count=1,
        scenario_base="benign_admin_ssh",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-3",
        dest_ports=[22],
        protocol="TCP",
        pkt_range=(15, 35),
        byte_mult_range=(110, 190),
        syn_ratio_range=(0.03, 0.08),
        payload_fn=lambda idx: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
        attack_sig="NIDS: Authorized System Administrator SSH Session",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.51",
        time_base=benign_base_time + datetime.timedelta(minutes=130),
        desc_template="Authorized key-based administrative remote console connection.",
    )

    # SMB file share x1: pc-1 -> pc-5
    add(
        count=1,
        scenario_base="benign_smb_share",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-5",
        dest_ports=[445],
        protocol="TCP",
        pkt_range=(30, 80),
        byte_mult_range=(320, 680),
        syn_ratio_range=(0.02, 0.06),
        payload_fn=lambda idx: "\\xffSMB2\\x00\\x00\\x00\\x00CreateRequest File",
        attack_sig="NIDS: Routine Enterprise File Share Access (SMB2)",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.25",
        time_base=benign_base_time + datetime.timedelta(minutes=160),
        desc_template="Normal user document read/write against corporate shared storage volume.",
    )

    # NTP sync x1: pc-3 -> pc-5
    add(
        count=1,
        scenario_base="benign_ntp",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-3",
        dst_node="pc-5",
        dest_ports=[123],
        protocol="UDP",
        pkt_range=(4, 12),
        byte_mult_range=(68, 76),
        syn_ratio_range=(0.00, 0.00),
        payload_fn=lambda idx: "\\x1b\\x00\\x00\\x00\\x00\\x00\\x00\\x00NTPClientSync",
        attack_sig="NIDS: Routine NTP Network Time Synchronization",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.51",
        orig_dst_ip="192.168.10.25",
        time_base=benign_base_time + datetime.timedelta(minutes=180),
        desc_template="Standard time synchronization query between Linux host and local timekeeper.",
    )

    # ICMP ping x1: pc-1 -> pc-3 (dest_port 1 placeholder)
    add(
        count=1,
        scenario_base="benign_icmp_ping",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-3",
        dest_ports=[1],
        protocol="ICMP",
        pkt_range=(4, 10),
        byte_mult_range=(64, 84),
        syn_ratio_range=(0.00, 0.00),
        payload_fn=lambda idx: "",
        attack_sig="NIDS: Normal Host Health Ping Check (ICMP Echo)",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.51",
        time_base=benign_base_time + datetime.timedelta(minutes=200),
        desc_template="Standard network reachability verification echo request/reply.",
    )

    # legit FTP x1: pc-1 -> pc-3 (bulk transfer)
    add(
        count=1,
        scenario_base="benign_ftp_transfer",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-3",
        dest_ports=[21],
        protocol="TCP",
        pkt_range=(1100, 2100),
        byte_mult_range=(980, 1380),
        syn_ratio_range=(0.002, 0.008),
        payload_fn=lambda idx: "USER anonymous\r\nPASS guest@zephyr.lan\r\nRETR dataset.tar.gz\r\n",
        attack_sig="NIDS: Authorized File Transfer Protocol Download",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.51",
        time_base=benign_base_time + datetime.timedelta(minutes=220),
        desc_template="Legitimate bulk data transfer downloading engineering archives.",
    )

    # LDAP bind x1: pc-1 -> pc-5
    add(
        count=1,
        scenario_base="benign_ldap_bind",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-5",
        dest_ports=[389],
        protocol="TCP",
        pkt_range=(12, 35),
        byte_mult_range=(120, 240),
        syn_ratio_range=(0.03, 0.08),
        payload_fn=lambda idx: "LDAP bindRequest(1) 'cn=admin,dc=zephyr,dc=lan' simple",
        attack_sig="NIDS: Standard Active Directory LDAP Authentication",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.25",
        time_base=benign_base_time + datetime.timedelta(minutes=240),
        desc_template="Normal user workstation domain credential validation against Active Directory.",
    )

    # One hard negative: legitimate traffic surge (1.5k-3k HTTP pkts, normal GET paths, conf 0.58-0.75)
    add(
        count=1,
        scenario_base="benign_surge_hard_neg",
        source_dataset="SYNTHETIC_BENIGN",
        original_label="Benign",
        src_node="pc-1",
        dst_node="pc-4",
        dest_ports=[80],
        protocol="HTTP",
        pkt_range=(1800, 2800),
        byte_mult_range=(480, 850),
        syn_ratio_range=(0.02, 0.05),
        payload_fn=lambda idx: "GET /api/v2/items?page=1&limit=50 HTTP/1.1\r\nHost: 172.28.0.14\r\nAccept: application/json\r\n",
        attack_sig="NIDS: High-Volume Legitimate Web API Query Burst",
        mitre_tactic="None",
        mitre_tech="T0000",
        severity="LOW",
        true_class="BENIGN",
        enum_fit="exact",
        acceptable_actions=["noop"],
        expected_noop=True,
        orig_src_ip="192.168.10.8",
        orig_dst_ip="192.168.10.50",
        time_base=benign_base_time + datetime.timedelta(minutes=270),
        desc_template="Sudden marketing flash-sale traffic surge with authentic user agent and valid API tokens.",
        hard_negative=True,
        ambiguous_indices=[0],  # 1 ambiguous
    )

    if len(scenarios) != 100:
        raise RuntimeError(f"Scenario count mismatch: expected exactly 100, got {len(scenarios)}")

    return scenarios


def generate_dataset(
    seed: int = 42,
    order: str = "shuffle",
    rebase_now: bool = False,
    output_dataset_path: str = "data/nids_alerts_dataset.jsonl",
    output_labels_path: str = "data/nids_alerts_labels.jsonl",
) -> Tuple[List[NIDSAlert], List[NIDSAlertLabel]]:
    """Generate exactly 100 records and validate them against Contract A and Sidecar schemas."""
    rng = random.Random(seed)
    raw_scenarios = build_scenario_instances(rng)

    # Assign deterministic UUIDs
    for item in raw_scenarios:
        uid = make_uuid4(rng)
        item["contract_a"]["alert_id"] = uid
        item["sidecar"]["alert_id"] = uid

    # Handle --rebase-now or chronological ordering
    if rebase_now:
        raw_scenarios.sort(key=lambda x: x["contract_a"]["timestamp"])
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        start_utc = now_utc - datetime.timedelta(seconds=(len(raw_scenarios) - 1) * 5)
        for i, item in enumerate(raw_scenarios):
            dt = start_utc + datetime.timedelta(seconds=i * 5)
            dt_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            item["contract_a"]["timestamp"] = dt_str

    if order == "chronological":
        raw_scenarios.sort(key=lambda x: x["contract_a"]["timestamp"])
    elif order == "shuffle":
        rng.shuffle(raw_scenarios)

    # Parse and validate every item with Pydantic
    alerts: List[NIDSAlert] = []
    labels: List[NIDSAlertLabel] = []

    for idx, item in enumerate(raw_scenarios):
        try:
            alert_obj = NIDSAlert.model_validate(item["contract_a"])
            label_obj = NIDSAlertLabel.model_validate(item["sidecar"])
            alerts.append(alert_obj)
            labels.append(label_obj)
        except Exception as e:
            raise RuntimeError(f"Validation failed on record {idx}: {e}") from e

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(output_dataset_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(output_labels_path)), exist_ok=True)

    # Write Contract A (minified JSONL, no trailing blank lines)
    with open(output_dataset_path, "w", encoding="utf-8", newline="\n") as f:
        for alert in alerts:
            line = json.dumps(alert.model_dump(), separators=(",", ":"), ensure_ascii=False)
            f.write(line + "\n")

    # Write Sidecar (minified JSONL, no trailing blank lines)
    with open(output_labels_path, "w", encoding="utf-8", newline="\n") as f:
        for label in labels:
            line = json.dumps(label.model_dump(), separators=(",", ":"), ensure_ascii=False)
            f.write(line + "\n")

    return alerts, labels


# ==============================================================================
# Validation & Reporting
# ==============================================================================

def validate_dataset_file(filepath: str) -> bool:
    """Validate a dataset file line by line against Contract A and hard rules."""
    if not os.path.isfile(filepath):
        print(f"[FAIL] File not found: {filepath}")
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    print(f"Validating '{filepath}': found {len(lines)} records.")

    if len(lines) != 100:
        print(f"[FAIL] Expected exactly 100 lines, found {len(lines)}")
        return False

    seen_ids = set()
    benign_count = 0
    valid_count = 0

    for i, line in enumerate(lines, 1):
        try:
            data = json.loads(line)
            alert = NIDSAlert.model_validate(data)
            if alert.alert_id in seen_ids:
                print(f"[FAIL] Duplicate alert_id at line {i}: {alert.alert_id}")
                return False
            seen_ids.add(alert.alert_id)

            if alert.nids_llm_assessment.mitre_tactic == "None":
                benign_count += 1
            valid_count += 1
        except Exception as e:
            print(f"[FAIL] Error validating line {i}: {e}")
            return False

    print(f"[PASS] Successfully validated {valid_count} lines. 0 invalid. {benign_count} benign alerts.")
    return True


def print_distribution_report(alerts: List[NIDSAlert], labels: List[NIDSAlertLabel]) -> None:
    """Print comprehensive distribution report as requested."""
    total = len(alerts)
    class_counts = Counter(l.true_class for l in labels)
    severity_counts = Counter(a.nids_llm_assessment.severity for a in alerts)
    protocol_counts = Counter(a.protocol for a in alerts)
    node_pair_counts = Counter(f"{a.source_node} -> {a.target_node}" for a in alerts)
    benign_share = (class_counts.get("BENIGN", 0) / total) * 100

    ambiguous_count = sum(1 for a in alerts if 0.55 <= a.nids_llm_assessment.confidence_score <= 0.75)
    high_conf_count = sum(1 for a in alerts if 0.85 <= a.nids_llm_assessment.confidence_score <= 0.98)
    hard_neg_count = sum(1 for l in labels if l.hard_negative)

    print("\n" + "=" * 70)
    print(" PROJECT ZEPHYR: NIDSALERT SYNTHETIC DATASET DISTRIBUTION REPORT ")
    print("=" * 70)
    print(f"Total Records: {total}")
    print(f"Benign Share:  {class_counts.get('BENIGN', 0)} / {total} ({benign_share:.1f}%) [Hard Negatives: {hard_neg_count}]")
    print(f"Confidence:    High (0.85-0.98): {high_conf_count}% | Ambiguous (0.55-0.75): {ambiguous_count}%")

    print("\n--- 1. Ground Truth True Class Distribution ---")
    for cls_name, cnt in sorted(class_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / total) * 100
        print(f"  {cls_name:<20}: {cnt:>3} ({pct:>5.1f}%)")

    print("\n--- 2. Severity Distribution ---")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = severity_counts.get(sev, 0)
        pct = (cnt / total) * 100
        print(f"  {sev:<12}: {cnt:>3} ({pct:>5.1f}%)")

    print("\n--- 3. Protocol Distribution ---")
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / total) * 100
        print(f"  {proto:<12}: {cnt:>3} ({pct:>5.1f}%)")

    print("\n--- 4. Node Communication Pairs ---")
    for pair, cnt in sorted(node_pair_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / total) * 100
        print(f"  {pair:<18}: {cnt:>3} ({pct:>5.1f}%)")

    print("=" * 70 + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generate Project Zephyr NIDSAlert synthetic dataset.")
    parser.add_argument(
        "--order",
        choices=["shuffle", "chronological"],
        default="shuffle",
        help="Alert sequence ordering (default: shuffle)",
    )
    parser.add_argument(
        "--rebase-now",
        action="store_true",
        help="Rebase timestamps to end at current UTC, 5s apart",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic output (default: 42)",
    )
    parser.add_argument(
        "--output-dataset",
        default="data/nids_alerts_dataset.jsonl",
        help="Output path for Contract A JSONL dataset",
    )
    parser.add_argument(
        "--output-labels",
        default="data/nids_alerts_labels.jsonl",
        help="Output path for Sidecar ground-truth labels",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory to place nids_alerts_dataset.jsonl and nids_alerts_labels.jsonl",
    )
    parser.add_argument(
        "--validate-only",
        metavar="FILE",
        help="Re-parse and validate an existing dataset file without generating new records",
    )

    args = parser.parse_args()

    if args.validate_only:
        success = validate_dataset_file(args.validate_only)
        sys.exit(0 if success else 1)

    output_dataset = args.output_dataset
    output_labels = args.output_labels
    if args.out_dir:
        output_dataset = os.path.join(args.out_dir, "nids_alerts_dataset.jsonl")
        output_labels = os.path.join(args.out_dir, "nids_alerts_labels.jsonl")

    alerts, labels = generate_dataset(
        seed=args.seed,
        order=args.order,
        rebase_now=args.rebase_now,
        output_dataset_path=output_dataset,
        output_labels_path=output_labels,
    )

    print(f"Generated {len(alerts)} Contract A records -> {output_dataset}")
    print(f"Generated {len(labels)} Sidecar labels     -> {output_labels}")

    print_distribution_report(alerts, labels)


if __name__ == "__main__":
    main()
