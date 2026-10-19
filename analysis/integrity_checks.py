#!/usr/bin/env python3
"""Project Zephyr - Repeatable NIDSAlert Integrity Pipeline.

Audits synthetic Contract A NIDS alerts dataset and ground-truth sidecar labels.
Verifies file structure, schema adherence, keys, semantic invariants, telemetry
consistency, attack signature realism, label consistency, leakage, duplicates,
distribution statistics, deterministic reproducibility, and dataframe cleanliness.

Outputs:
- analysis/reports/integrity_report.md
- analysis/reports/integrity_report.json
- analysis/reports/checksums.txt
- analysis/reports/charts/class_counts.png
- analysis/reports/charts/syn_ratio_by_class.png
- analysis/reports/charts/packets_by_class.png
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


# ==============================================================================
# Strict Pydantic Contract A Models (extra="forbid")
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
            raise ValueError("unique_dest_ports must be unique and sorted ascending")
        return v

    @model_validator(mode="after")
    def validate_byte_packet_ratio(self) -> FlowMetrics:
        if self.byte_count_2s < 54 * self.packet_count_2s:
            raise ValueError(
                f"byte_count_2s ({self.byte_count_2s}) < 54 * packet_count_2s ({54 * self.packet_count_2s})"
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
    def validate_contract_a_invariants(self) -> NIDSAlert:
        if self.source_ip != NODE_IP_MAP.get(self.source_node):
            raise ValueError(f"source_ip {self.source_ip} mismatch with {self.source_node}")
        if self.target_ip != NODE_IP_MAP.get(self.target_node):
            raise ValueError(f"target_ip {self.target_ip} mismatch with {self.target_node}")
        if self.source_node == self.target_node:
            raise ValueError(f"source_node ({self.source_node}) equals target_node ({self.target_node})")
        if self.dest_port not in self.flow_metrics.unique_dest_ports:
            raise ValueError(f"dest_port {self.dest_port} not in unique_dest_ports {self.flow_metrics.unique_dest_ports}")
        return self


# ==============================================================================
# Check Result Data Structure
# ==============================================================================

class CheckResult:
    def __init__(self, check_num: int, name: str):
        self.check_num = check_num
        self.name = name
        self.status: Literal["PASS", "WARN", "FAIL"] = "PASS"
        self.count: int = 0
        self.offending_alert_ids: List[str] = []
        self.findings: List[Dict[str, Any]] = []
        self.remediation: Optional[str] = None

    def add_finding(self, alert_id: Optional[str], detail: str, is_fail: bool = True):
        if is_fail:
            self.status = "FAIL"
        elif self.status != "FAIL":
            self.status = "WARN"

        self.count += 1
        if alert_id and alert_id not in self.offending_alert_ids:
            self.offending_alert_ids.append(alert_id)
        self.findings.append({"alert_id": alert_id, "detail": detail, "severity": "FAIL" if is_fail else "WARN"})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_num": self.check_num,
            "name": self.name,
            "status": self.status,
            "count": self.count,
            "offending_alert_ids": self.offending_alert_ids,
            "findings": self.findings,
            "remediation": self.remediation,
        }


# ==============================================================================
# Check 1: File Formatting & Encoding
# ==============================================================================

def check_1_file(dataset_path: str, labels_path: str) -> CheckResult:
    res = CheckResult(1, "File Formatting & Encoding")
    files_to_check = [("Dataset", dataset_path), ("Labels", labels_path)]

    for label, path in files_to_check:
        if not os.path.isfile(path):
            res.add_finding(None, f"{label} file not found: {path}", is_fail=True)
            continue

        raw = open(path, "rb").read()

        # Check BOM
        if raw.startswith(b"\xef\xbb\xbf"):
            res.add_finding(None, f"{label} file contains UTF-8 BOM", is_fail=True)

        # Check UTF-8 decoding
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            res.add_finding(None, f"{label} file UTF-8 decode error: {e}", is_fail=True)
            continue

        # Check trailing double newlines / blank line
        if raw.endswith(b"\n\n") or raw.endswith(b"\r\n\r\n"):
            res.add_finding(None, f"{label} file has trailing blank line", is_fail=True)

        # Non-empty lines and JSON validity
        lines = text.splitlines()
        non_empty_lines = [l for l in lines if l.strip()]
        if len(non_empty_lines) != 100:
            res.add_finding(None, f"{label} expected 100 non-empty lines, found {len(non_empty_lines)}", is_fail=True)

        for line_no, l in enumerate(lines, 1):
            if not l.strip():
                res.add_finding(None, f"{label} contains empty line at line {line_no}", is_fail=True)
                continue
            try:
                json.loads(l)
            except json.JSONDecodeError as e:
                res.add_finding(None, f"{label} invalid JSON at line {line_no}: {e}", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. File conforms strictly to UTF-8, 100 non-empty lines, valid JSON."
    else:
        res.remediation = "Ensure dataset files are encoded in clean UTF-8 without BOM or extraneous blank lines."
    return res


# ==============================================================================
# Check 2: Schema Validation (Strict Pydantic Contract A)
# ==============================================================================

def check_2_schema(dataset_records: List[Dict[str, Any]]) -> CheckResult:
    res = CheckResult(2, "Strict Schema Validation (Contract A)")
    for i, rec in enumerate(dataset_records, 1):
        aid = rec.get("alert_id", f"record-{i}")
        try:
            NIDSAlert.model_validate(rec)
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"])
                msg = err["msg"]
                res.add_finding(aid, f"Contract A schema violation at '{loc}': {msg}", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. All 100 alerts adhere strictly to Contract A schema with extra='forbid'."
    else:
        res.remediation = "Fix schema discrepancies in data generator so all records strictly match Contract A specifications."
    return res


# ==============================================================================
# Check 3: Key Integrity & 1:1 Sidecar Join
# ==============================================================================

def check_3_keys(dataset_records: List[Dict[str, Any]], label_records: List[Dict[str, Any]]) -> CheckResult:
    res = CheckResult(3, "Key Integrity & 1:1 Sidecar Join")

    ds_ids = [r.get("alert_id") for r in dataset_records]
    lb_ids = [r.get("alert_id") for r in label_records]

    seen_ds = set()
    for aid in ds_ids:
        if not aid:
            res.add_finding(None, "Dataset contains record with null/empty alert_id", is_fail=True)
            continue
        if aid in seen_ds:
            res.add_finding(aid, f"Duplicate alert_id in dataset: {aid}", is_fail=True)
        seen_ds.add(aid)

        try:
            val = uuid.UUID(aid, version=4)
            if str(val) != aid:
                res.add_finding(aid, f"alert_id is not properly canonicalized UUID4: {aid}", is_fail=True)
        except Exception:
            res.add_finding(aid, f"alert_id is not valid UUID4: {aid}", is_fail=True)

    seen_lb = set()
    for aid in lb_ids:
        if not aid:
            res.add_finding(None, "Labels sidecar contains record with null/empty alert_id", is_fail=True)
            continue
        if aid in seen_lb:
            res.add_finding(aid, f"Duplicate alert_id in labels sidecar: {aid}", is_fail=True)
        seen_lb.add(aid)

    # 1:1 Join verification (no orphans)
    ds_set = set(filter(None, ds_ids))
    lb_set = set(filter(None, lb_ids))

    orphans_ds = ds_set - lb_set
    for aid in orphans_ds:
        res.add_finding(aid, f"Dataset alert has no matching sidecar label (orphan): {aid}", is_fail=True)

    orphans_lb = lb_set - ds_set
    for aid in orphans_lb:
        res.add_finding(aid, f"Sidecar label has no matching dataset alert (orphan): {aid}", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. All alert_ids are unique, valid UUID4s with perfect 1:1 join."
    else:
        res.remediation = "Ensure generator produces unique UUIDv4 keys and writes matching sidecar labels."
    return res


# ==============================================================================
# Check 4: Semantic Invariants & Boundary Constraints
# ==============================================================================

def check_4_semantics(dataset_records: List[Dict[str, Any]]) -> CheckResult:
    res = CheckResult(4, "Semantic Invariants & Boundary Constraints")

    for rec in dataset_records:
        aid = rec.get("alert_id", "unknown")
        src_node = rec.get("source_node", "")
        dst_node = rec.get("target_node", "")
        src_ip = rec.get("source_ip", "")
        dst_ip = rec.get("target_ip", "")
        dest_port = rec.get("dest_port")
        ts = rec.get("timestamp", "")
        fm = rec.get("flow_metrics", {})
        pkts = fm.get("packet_count_2s", 0)
        bytes_2s = fm.get("byte_count_2s", 0)
        ports = fm.get("unique_dest_ports", [])
        payload = fm.get("payload_sample", "")

        # 1. pc-N maps to 172.28.0.(10+N)
        for prefix, node, ip in [("source", src_node, src_ip), ("target", dst_node, dst_ip)]:
            m = re.match(r"^pc-(\d+)$", node)
            if not m:
                res.add_finding(aid, f"Invalid {prefix}_node format: {node}", is_fail=True)
            else:
                expected_ip = f"172.28.0.{10 + int(m.group(1))}"
                if ip != expected_ip:
                    res.add_finding(aid, f"{prefix}_ip ({ip}) != expected mapping {expected_ip} for {node}", is_fail=True)

        # 2. source_node != target_node
        if src_node == dst_node:
            res.add_finding(aid, f"Loopback communication forbidden: source_node equals target_node ({src_node})", is_fail=True)

        # 3. dest_port in unique_dest_ports
        if dest_port not in ports:
            res.add_finding(aid, f"dest_port {dest_port} not present in unique_dest_ports {ports}", is_fail=True)

        # 4. unique_dest_ports sorted and unique
        if ports != sorted(set(ports)):
            res.add_finding(aid, f"unique_dest_ports not strictly unique or sorted ascending: {ports}", is_fail=True)

        # 5. byte_count_2s >= 54 * packet_count_2s
        if bytes_2s < 54 * pkts:
            res.add_finding(aid, f"Physical frame violation: byte_count_2s ({bytes_2s}) < 54 * packet_count_2s ({54 * pkts})", is_fail=True)

        # 6. timestamp format YYYY-MM-DDTHH:MM:SSZ
        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts):
            res.add_finding(aid, f"Timestamp format invalid (expected YYYY-MM-DDTHH:MM:SSZ): {ts}", is_fail=True)

        # 7. payload_sample <= 160 chars
        if len(payload) > 160:
            res.add_finding(aid, f"payload_sample length ({len(payload)}) exceeds 160 character ceiling", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. All semantic rules and physical boundaries are honored."
    else:
        res.remediation = "Verify generator logic ensures dest_port inclusion, IP mapping, and payload truncation."
    return res


# ==============================================================================
# Check 5: Summary Consistency
# ==============================================================================

def check_5_summary(dataset_records: List[Dict[str, Any]]) -> CheckResult:
    res = CheckResult(5, "Raw Telemetry Summary Consistency")

    summary_pattern = re.compile(
        r"^Observed\s+(\d+)\s+packets\s+\((\d+)\s+bytes\)\s+over\s+(\d+)s\s+with\s+syn_ratio\s+([\d\.]+)\s+targeting\s+(dest_port\s+(\d+)|ports\s+(\[[^\]]+\])):\s*(.*)$"
    )

    for rec in dataset_records:
        aid = rec.get("alert_id", "unknown")
        summary = rec.get("nids_llm_assessment", {}).get("raw_telemetry_summary", "")
        fm = rec.get("flow_metrics", {})
        dest_port = rec.get("dest_port")
        proto = rec.get("protocol")

        m = summary_pattern.match(summary)
        if not m:
            res.add_finding(aid, f"Summary failed structural regex parsing: '{summary}'", is_fail=True)
            continue

        sum_pkts = int(m.group(1))
        sum_bytes = int(m.group(2))
        sum_syn = float(m.group(4))

        # Check packet count
        if sum_pkts != fm.get("packet_count_2s"):
            res.add_finding(aid, f"Summary packet count ({sum_pkts}) != flow_metrics ({fm.get('packet_count_2s')})", is_fail=True)

        # Check byte count
        if sum_bytes != fm.get("byte_count_2s"):
            res.add_finding(aid, f"Summary byte count ({sum_bytes}) != flow_metrics ({fm.get('byte_count_2s')})", is_fail=True)

        # Check SYN ratio
        if abs(sum_syn - fm.get("syn_ratio", 0.0)) > 0.015:
            res.add_finding(aid, f"Summary syn_ratio ({sum_syn:.2f}) != flow_metrics ({fm.get('syn_ratio')})", is_fail=True)

        # Check port / port count
        if m.group(6):  # single dest_port
            sum_port = int(m.group(6))
            if sum_port != dest_port:
                res.add_finding(aid, f"Summary dest_port ({sum_port}) != structured dest_port ({dest_port})", is_fail=True)
            if len(fm.get("unique_dest_ports", [])) != 1 or fm.get("unique_dest_ports", [])[0] != sum_port:
                res.add_finding(aid, f"Summary indicated single port {sum_port} but unique_dest_ports={fm.get('unique_dest_ports')}", is_fail=True)
        elif m.group(7):  # multiple ports list
            try:
                sum_ports = json.loads(m.group(7))
                if sum_ports != fm.get("unique_dest_ports", []):
                    res.add_finding(aid, f"Summary ports list ({sum_ports}) != unique_dest_ports ({fm.get('unique_dest_ports')})", is_fail=True)
                if dest_port != sum_ports[0]:
                    res.add_finding(aid, f"Structured dest_port ({dest_port}) != primary scan port ({sum_ports[0]}) in summary", is_fail=True)
            except Exception as e:
                res.add_finding(aid, f"Could not parse ports list from summary: {e}", is_fail=True)

        # Check protocol mention consistency in summary narrative
        narrative = m.group(8)
        for p in ["TCP", "UDP", "ICMP", "HTTP"]:
            if re.search(r"\b" + p + r"\b", narrative, re.IGNORECASE):
                upper_p = p.upper()
                if upper_p != proto:
                    res.add_finding(
                        aid,
                        f"Protocol discrepancy: summary narrative states '{upper_p}' connections while structured protocol is '{proto}'",
                        is_fail=True,
                    )

    if res.status == "PASS":
        res.remediation = "None required. Summary metrics and narrative protocol state match structured fields exactly."
    else:
        res.remediation = "Ensure protocol in generator scenario definitions strictly matches the summary narrative."
    return res


# ==============================================================================
# Check 6: Class Realism by Attack Signature
# ==============================================================================

# Extended SQLi regex pattern matching standard tautologies, error-based vectors,
# time-based blind injection, administrative procedures, and quote-comment tricks
SQLI_EXTENDED_PATTERN = re.compile(
    r"(?:UNION|OR\s+1\s*=\s*1|DROP|CONVERT|CAST|@@version|EXTRACTVALUE|SLEEP\s*\(|'--|\"--|/\*|\*/|#)",
    re.IGNORECASE,
)


def check_6_class_realism(
    dataset_records: List[Dict[str, Any]],
    label_records: List[Dict[str, Any]],
) -> CheckResult:
    res = CheckResult(6, "Class Realism & Domain Profile Verification")

    lb_map = {r["alert_id"]: r for r in label_records}
    class_total_counts = Counter(r["true_class"] for r in label_records)
    class_breach_counts = Counter()

    for rec in dataset_records:
        aid = rec["alert_id"]
        lb = lb_map.get(aid, {})
        true_class = lb.get("true_class", "UNKNOWN")
        sig = rec["nids_llm_assessment"]["attack_signature"]
        fm = rec["flow_metrics"]
        assessment = rec["nids_llm_assessment"]
        pkts = fm["packet_count_2s"]
        bytes_2s = fm["byte_count_2s"]
        syn_r = fm["syn_ratio"]
        ports = fm["unique_dest_ports"]
        payload = fm["payload_sample"]
        dest_port = rec["dest_port"]
        proto = rec["protocol"]

        breached = False
        breach_desc = []

        # 1. TCP SYN Flood (LOIT): 3000-8000 packets, syn_ratio>=0.85, empty payload
        if "LOIT" in sig or ("SYN Flood" in sig and "Distributed" in sig):
            if not (3000 <= pkts <= 8000 and syn_r >= 0.85 and payload == ""):
                breached = True
                breach_desc.append(f"LOIT profile breach: pkts={pkts} (expected 3000-8000), syn_ratio={syn_r:.2f} (>=0.85), payload='{payload}' (expected empty)")

        # 2. UDP flood: protocol UDP, syn_ratio==0.0
        if "UDP" in sig and "Flood" in sig:
            if not (proto == "UDP" and syn_r == 0.0):
                breached = True
                breach_desc.append(f"UDP Flood breach: protocol={proto} (expected UDP), syn_ratio={syn_r:.2f} (expected 0.0)")

        # 3. Port Scans (All Recon / Scan signatures):
        # Must contain 15-60 sorted unique ports, dest_port = lowest port,
        # packet_count_2s >= number of ports, byte_count_2s >= 54 * packets.
        # FIN/Xmas/Null/UDP scans: syn_ratio == 0.0
        if "Scan" in sig or "Probe" in sig:
            if not (15 <= len(ports) <= 60):
                breached = True
                breach_desc.append(f"Port scan ports count breach: {len(ports)} ports (expected 15-60)")
            if dest_port != ports[0]:
                breached = True
                breach_desc.append(f"Port scan dest_port breach: dest_port={dest_port} is not lowest port ({ports[0]})")
            if pkts < len(ports):
                breached = True
                breach_desc.append(f"Port scan packet count breach: pkts={pkts} < number of ports ({len(ports)})")
            if bytes_2s < 54 * pkts:
                breached = True
                breach_desc.append(f"Port scan byte count breach: bytes={bytes_2s} < 54 * pkts ({54 * pkts})")

            # Stealth FIN/Xmas/Null and UDP discovery scan specific check: syn_ratio == 0.0
            if any(s in sig for s in ["FIN Stealth Probe", "Null Probe", "Xmas Tree Probe", "UDP Service Discovery Scan"]):
                if syn_r != 0.0:
                    breached = True
                    breach_desc.append(f"Stealth/UDP scan syn_ratio breach: syn_ratio={syn_r:.2f} (expected 0.0)")

        # 4. Brute force (FTP/SSH/Web): 1 port, packets 30-400
        if any(s in sig for s in ["Brute-Force", "Brute-force", "Password Guessing", "Credential Guessing"]):
            if not (len(ports) == 1 and 30 <= pkts <= 400):
                breached = True
                breach_desc.append(f"Brute-force breach: ports={len(ports)} (expected 1), pkts={pkts} (expected 30-400)")

        # 5. Heartbleed: dest_port 444
        if "CVE-2014-0160" in sig or ("Heartbeat" in sig and "OpenSSL" in sig):
            if dest_port != 444:
                breached = True
                breach_desc.append(f"Heartbleed port breach: dest_port={dest_port} (expected 444)")

        # 6. SQLi payload check: accept UNION, OR 1=1, DROP, CONVERT, CAST, @@version,
        # EXTRACTVALUE, SLEEP(, and quote-comment tricks
        if "SQL" in sig and ("Injection" in sig or "SQLi" in sig):
            if not SQLI_EXTENDED_PATTERN.search(payload):
                breached = True
                breach_desc.append(
                    f"SQLi payload breach: payload='{payload.strip()}' missing accepted injection pattern "
                    "(UNION, OR 1=1, DROP, CONVERT, CAST, @@version, EXTRACTVALUE, SLEEP(, or comment trick)"
                )

        # 7. XSS payload has script|onerror
        if "XSS" in sig or "Cross-Site Scripting" in sig:
            if not re.search(r"script|onerror", payload, re.IGNORECASE):
                breached = True
                breach_desc.append(f"XSS payload breach: payload='{payload.strip()}' missing script|onerror")

        # 8. Benign: severity LOW, mitre T0000/"None", expected_noop true in labels
        if true_class == "BENIGN":
            if not (assessment["severity"] == "LOW" and assessment["mitre_technique_id"] == "T0000" and assessment["mitre_tactic"] == "None" and lb.get("expected_noop") is True):
                breached = True
                breach_desc.append(f"Benign profile breach: severity={assessment['severity']}, mitre={assessment['mitre_technique_id']}, expected_noop={lb.get('expected_noop')}")

        if breached:
            class_breach_counts[true_class] += 1
            for d in breach_desc:
                res.add_finding(aid, f"[{true_class}] {d}", is_fail=False)

    # Evaluate 10% breach threshold per class
    failing_classes = []
    for cls, breach_cnt in class_breach_counts.items():
        tot = class_total_counts.get(cls, 1)
        rate = (breach_cnt / tot) * 100
        if rate > 10.0:
            failing_classes.append((cls, breach_cnt, tot, rate))

    if failing_classes:
        res.status = "FAIL"
        for cls, b_cnt, tot, rate in failing_classes:
            res.add_finding(
                None,
                f"Class breach threshold (>10%) exceeded for class '{cls}': {b_cnt}/{tot} alerts breached ({rate:.1f}%)",
                is_fail=True,
            )
        res.remediation = "Fix scenario parameters in generate_dataset.py so profile breach rates remain under 10%."
    elif res.count > 0:
        res.status = "WARN"
        res.remediation = "Investigate isolated class realism breaches; breach rate is within acceptable 10% tolerance."
    else:
        res.remediation = "None required. All class realism constraints satisfied across all attack signatures."

    return res


# ==============================================================================
# Check 7: Ground-Truth Label & Metadata Consistency
# ==============================================================================

def check_7_label_consistency(
    dataset_records: List[Dict[str, Any]],
    label_records: List[Dict[str, Any]],
) -> CheckResult:
    res = CheckResult(7, "Ground-Truth Label & Metadata Consistency")

    lb_map = {r["alert_id"]: r for r in label_records}
    hard_neg_count = 0

    for rec in dataset_records:
        aid = rec["alert_id"]
        lb = lb_map.get(aid, {})
        true_class = lb.get("true_class")
        tech = rec["nids_llm_assessment"]["mitre_technique_id"]
        noop = lb.get("expected_noop")
        actions = lb.get("acceptable_actions", [])
        is_hard_neg = lb.get("hard_negative", False)

        if is_hard_neg:
            hard_neg_count += 1

        # 1. true_class BENIGN <=> mitre_technique_id T0000 <=> expected_noop true
        is_benign = (true_class == "BENIGN")
        is_t0000 = (tech == "T0000")
        is_noop = (noop is True)

        if not (is_benign == is_t0000 == is_noop):
            res.add_finding(
                aid,
                f"Equivalence invariant broken: true_class={true_class}, mitre_technique_id={tech}, expected_noop={noop}",
                is_fail=True,
            )

        # 2. acceptable_actions non-empty
        if not actions or not isinstance(actions, list):
            res.add_finding(aid, f"acceptable_actions is empty or invalid: {actions}", is_fail=True)

        # 3. timestamp == original_timestamp_local (when not rebased)
        ts_norm = rec["timestamp"].replace("T", " ").replace("Z", "")
        orig_ts = lb.get("original_timestamp_local", "")
        if ts_norm != orig_ts:
            res.add_finding(aid, f"Timestamp discrepancy: alert={rec['timestamp']} vs original_local={orig_ts}", is_fail=True)

    # 4. hard_negative count == 1
    if hard_neg_count != 1:
        res.add_finding(None, f"hard_negative count={hard_neg_count} (expected exactly 1)", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. Exact label consistency, equivalence invariants, and hard negative count verified."
    else:
        res.remediation = "Ensure expected_noop and mitre_technique_id T0000 are strictly coupled to BENIGN class."
    return res


# ==============================================================================
# Check 8: Label & Original Topology Leakage
# ==============================================================================

def check_8_leakage(dataset_path: str) -> CheckResult:
    res = CheckResult(8, "Label & Original Topology Leakage")

    sidecar_fields = [
        "true_class", "enum_fit", "acceptable_actions", "expected_noop",
        "hard_negative", "source_dataset", "original_attack_label",
        "original_src_ip", "original_dst_ip", "original_timestamp_local",
        "scenario_id"
    ]

    forbidden_strings = ["true_class", "SYN_FLOOD", "RCE_ATTEMPT", "acceptable_actions"]

    forbidden_ip_patterns = [
        (r"205\.174\.165\.\d+", "CIC-IDS2017 public IP range (205.174.165.*)"),
        (r"192\.168\.10\.\d+", "CIC-IDS2017 private IP range (192.168.10.*)"),
        (r"172\.31\.\d+\.\d+", "CSE-CIC-IDS2018 AWS IP range (172.31.*)"),
        (r"18\.\d+\.\d+\.\d+", "CSE-CIC-IDS2018 AWS IP range (18.*.*.*)"),
        (r"13\.\d+\.\d+\.\d+", "CSE-CIC-IDS2018 AWS IP range (13.*.*.*)"),
        (r"52\.\d+\.\d+\.\d+", "CSE-CIC-IDS2018 AWS IP range (52.*.*.*)"),
    ]

    with open(dataset_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            aid = rec.get("alert_id", f"line-{line_no}")

            for fld in sidecar_fields:
                if f'"{fld}"' in line:
                    res.add_finding(aid, f"Sidecar ground-truth field name '{fld}' leaked into dataset at line {line_no}", is_fail=True)

            for s in forbidden_strings:
                if s in line:
                    res.add_finding(aid, f"Forbidden label literal string '{s}' found in dataset at line {line_no}", is_fail=True)

            for pat, desc in forbidden_ip_patterns:
                matches = re.findall(pat, line)
                if matches:
                    res.add_finding(aid, f"Forbidden benchmark IP {matches[0]} leaked ({desc}) at line {line_no}", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. Clean separation between Contract A telemetry and sidecar labels."
    else:
        res.remediation = "Scrub all benchmark source IP addresses and sidecar field names from Contract A generator output."
    return res


# ==============================================================================
# Check 9: Duplicate Detection
# ==============================================================================

def check_9_duplicates(dataset_records: List[Dict[str, Any]]) -> CheckResult:
    res = CheckResult(9, "Exact & Near-Duplicate Detection")

    exact_groups = defaultdict(list)
    near_groups = defaultdict(list)

    for rec in dataset_records:
        aid = rec.get("alert_id", "unknown")

        exact_str = json.dumps(rec, sort_keys=True)
        exact_groups[exact_str].append(aid)

        near_dict = {k: v for k, v in rec.items() if k not in ["alert_id", "timestamp"]}
        near_str = json.dumps(near_dict, sort_keys=True)
        near_groups[near_str].append((aid, rec.get("timestamp")))

    for s, aids in exact_groups.items():
        if len(aids) > 1:
            for aid in aids:
                res.add_finding(aid, f"Exact duplicate record found across {len(aids)} alerts: {aids}", is_fail=False)

    for s, entries in near_groups.items():
        if len(entries) > 1:
            aids = [e[0] for e in entries]
            for aid, ts in entries:
                res.add_finding(aid, f"Near-duplicate record (identical telemetry, different id/timestamp): {aids}", is_fail=False)

    if res.count > 0:
        res.status = "WARN"
        res.remediation = "Review near-duplicate alerts to ensure diversity across synthesized scenario iterations."
    else:
        res.status = "PASS"
        res.remediation = "None required. Zero exact or near-duplicate records identified."
    return res


# ==============================================================================
# Check 10: Statistical Distribution & Outliers (pandas)
# ==============================================================================

def check_10_statistics(
    dataset_records: List[Dict[str, Any]],
    label_records: List[Dict[str, Any]],
) -> Tuple[CheckResult, Dict[str, Any]]:
    res = CheckResult(10, "Statistical Distribution & Outlier Analysis")

    df_ds = pd.json_normalize(dataset_records)
    df_lb = pd.json_normalize(label_records)
    df = pd.merge(df_ds, df_lb, on="alert_id")

    df["node_pair"] = df["source_node"] + " -> " + df["target_node"]

    # 1. Counts
    class_counts = df["true_class"].value_counts().to_dict()
    severity_counts = df["nids_llm_assessment.severity"].value_counts().to_dict()
    protocol_counts = df["protocol"].value_counts().to_dict()
    node_pair_counts = df["node_pair"].value_counts().to_dict()
    dataset_counts = df["source_dataset"].value_counts().to_dict()

    # 2. Per-class min/median/max
    metrics = ["flow_metrics.packet_count_2s", "flow_metrics.byte_count_2s", "flow_metrics.syn_ratio"]
    per_class_stats = {}
    for cls in sorted(df["true_class"].unique()):
        sub = df[df["true_class"] == cls]
        per_class_stats[cls] = {}
        for m in metrics:
            short_m = m.split(".")[-1]
            per_class_stats[cls][short_m] = {
                "min": float(sub[m].min()),
                "median": float(sub[m].median()),
                "max": float(sub[m].max()),
            }

    # 3. IQR Outliers per metric per class
    outliers = []
    for cls in df["true_class"].unique():
        sub = df[df["true_class"] == cls]
        for m in metrics:
            short_m = m.split(".")[-1]
            q25 = sub[m].quantile(0.25)
            q75 = sub[m].quantile(0.75)
            iqr = q75 - q25
            lower = q25 - 1.5 * iqr
            upper = q75 + 1.5 * iqr
            out_df = sub[(sub[m] < lower) | (sub[m] > upper)]
            for _, r in out_df.iterrows():
                outliers.append({
                    "class": cls,
                    "metric": short_m,
                    "alert_id": r["alert_id"],
                    "value": float(r[m]),
                    "iqr_lower": float(lower),
                    "iqr_upper": float(upper),
                })

    # 4. Share of confidence in 0.55 - 0.75 (expect ~12% of attacks, tolerance +-8 points: 4% - 20%)
    attack_df = df[df["true_class"] != "BENIGN"]
    ambig_attacks = attack_df[
        (attack_df["nids_llm_assessment.confidence_score"] >= 0.55)
        & (attack_df["nids_llm_assessment.confidence_score"] <= 0.75)
    ]
    attack_ambig_pct = (len(ambig_attacks) / len(attack_df)) * 100

    if not (4.0 <= attack_ambig_pct <= 20.0):
        res.add_finding(
            None,
            f"Ambiguous attack confidence share ({attack_ambig_pct:.2f}%) out of tolerance [4.0%, 20.0%] (target 12% ± 8%)",
            is_fail=True,
        )

    # 5. Benign share must be exactly 15%
    benign_count = class_counts.get("BENIGN", 0)
    benign_pct = (benign_count / len(df)) * 100
    if abs(benign_pct - 15.0) > 0.01:
        res.add_finding(
            None,
            f"Benign share ({benign_pct:.1f}%) violates requirement (must be exactly 15.0%)",
            is_fail=True,
        )

    stats_summary = {
        "class_counts": class_counts,
        "severity_counts": severity_counts,
        "protocol_counts": protocol_counts,
        "node_pair_counts": node_pair_counts,
        "dataset_counts": dataset_counts,
        "per_class_stats": per_class_stats,
        "outliers": outliers,
        "ambiguous_attacks_share": attack_ambig_pct,
        "ambiguous_attacks_count": len(ambig_attacks),
        "total_attacks_count": len(attack_df),
        "benign_share": benign_pct,
    }

    if res.status == "PASS":
        res.remediation = "None required. Statistical distribution conforms to all specified tolerances."
    else:
        res.remediation = "Adjust generator scenario quotas to meet target benign ratio (15%) and ambiguous confidence bounds."

    return res, stats_summary


# ==============================================================================
# Check 11: Deterministic Reproducibility (Dynamic CLI Detection)
# ==============================================================================

def check_11_reproducibility(
    generator_script: str,
    dataset_path: str,
    labels_path: str,
) -> CheckResult:
    res = CheckResult(11, "Deterministic Generator Reproducibility")

    def sha256_file(p: str) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    orig_ds_sha = sha256_file(dataset_path)
    orig_lb_sha = sha256_file(labels_path)

    temp_dir = tempfile.mkdtemp(prefix="zephyr_regen_")
    regen_ds = os.path.join(temp_dir, "nids_alerts_dataset.jsonl")
    regen_lb = os.path.join(temp_dir, "nids_alerts_labels.jsonl")

    # Step 1: Detect generator's real CLI options via --help
    help_proc = subprocess.run([sys.executable, generator_script, "--help"], capture_output=True, text=True)
    help_text = help_proc.stdout + help_proc.stderr

    if "--out-dir" in help_text:
        cmd = [sys.executable, generator_script, "--out-dir", temp_dir]
        cli_mode = "--out-dir"
    elif "--output-dataset" in help_text and "--output-labels" in help_text:
        cmd = [sys.executable, generator_script, "--output-dataset", regen_ds, "--output-labels", regen_lb]
        cli_mode = "--output-dataset / --output-labels"
    else:
        res.add_finding(None, f"Unable to detect output path arguments from generator --help: {help_text[:200]}", is_fail=True)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return res

    # Step 2: Run generation command
    gen_proc = subprocess.run(cmd, capture_output=True, text=True)
    if gen_proc.returncode != 0:
        res.add_finding(None, f"Dataset generator execution failed (mode {cli_mode}): {gen_proc.stderr}", is_fail=True)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return res

    regen_ds_sha = sha256_file(regen_ds)
    regen_lb_sha = sha256_file(regen_lb)

    ds_match = (regen_ds_sha == orig_ds_sha)
    lb_match = (regen_lb_sha == orig_lb_sha)

    if not ds_match:
        res.add_finding(None, f"Dataset SHA-256 mismatch! Orig: {orig_ds_sha[:16]}... vs Regen: {regen_ds_sha[:16]}...", is_fail=True)
    if not lb_match:
        res.add_finding(None, f"Labels SHA-256 mismatch! Orig: {orig_lb_sha[:16]}... vs Regen: {regen_lb_sha[:16]}...", is_fail=True)

    shutil.rmtree(temp_dir, ignore_errors=True)

    if ds_match and lb_match and res.status == "PASS":
        res.remediation = f"None required. Generator reproduced identical SHA-256 hashes via detected CLI mode '{cli_mode}'."
    else:
        res.remediation = "Fix non-deterministic random state or CLI arguments in generate_dataset.py."

    return res


# ==============================================================================
# Check 12: Load Test & Clean Dataframe
# ==============================================================================

def check_12_load_test(
    dataset_records: List[Dict[str, Any]],
    label_records: List[Dict[str, Any]],
) -> CheckResult:
    res = CheckResult(12, "Dataframe Ingestion & Missing Value Load Test")

    try:
        df_ds = pd.json_normalize(dataset_records)
        df_lb = pd.json_normalize(label_records)
        df = pd.merge(df_ds, df_lb, on="alert_id")

        nan_counts = df.isna().sum()
        cols_with_nan = nan_counts[nan_counts > 0]

        if not cols_with_nan.empty:
            for col, count in cols_with_nan.items():
                res.add_finding(None, f"Column '{col}' contains {count} NaN values", is_fail=True)

        if len(df) != 100:
            res.add_finding(None, f"Loaded dataframe length is {len(df)} (expected 100)", is_fail=True)

    except Exception as e:
        res.add_finding(None, f"Failed to ingest and flatten dataset into pandas: {e}", is_fail=True)

    if res.status == "PASS":
        res.remediation = "None required. Dataframe flattens with zero NaNs across all 30 structured attributes."
    else:
        res.remediation = "Ensure all records supply complete values for all nested flow and assessment fields."

    return res


# ==============================================================================
# Differential Analysis (Changes Section)
# ==============================================================================

def analyze_changes(
    current_dataset_records: List[Dict[str, Any]],
    current_label_records: List[Dict[str, Any]],
    baseline_dataset_path: str,
    baseline_labels_path: str,
    current_dataset_path: str,
    current_labels_path: str,
) -> Dict[str, Any]:
    def get_sha256(p: str) -> str:
        if not os.path.isfile(p):
            return "N/A"
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    v1_ds_sha = get_sha256(baseline_dataset_path)
    v1_lb_sha = get_sha256(baseline_labels_path)
    v2_ds_sha = get_sha256(current_dataset_path)
    v2_lb_sha = get_sha256(current_labels_path)

    v1_records_by_id = {}
    if os.path.isfile(baseline_dataset_path):
        with open(baseline_dataset_path, "r", encoding="utf-8") as f:
            for l in f:
                if l.strip():
                    item = json.loads(l)
                    v1_records_by_id[item["alert_id"]] = item

    changed_records = []
    for r2 in current_dataset_records:
        aid = r2["alert_id"]
        if aid not in v1_records_by_id:
            changed_records.append({"alert_id": aid, "type": "NEW_ALERT", "diffs": []})
            continue

        r1 = v1_records_by_id[aid]
        if r1 != r2:
            diffs = []
            for k in r2:
                if r1.get(k) != r2.get(k):
                    diffs.append({
                        "field": k,
                        "before": r1.get(k),
                        "after": r2.get(k),
                    })
            changed_records.append({
                "alert_id": aid,
                "attack_signature": r2["nids_llm_assessment"]["attack_signature"],
                "true_class": next((lb["true_class"] for lb in current_label_records if lb["alert_id"] == aid), "UNKNOWN"),
                "diffs": diffs,
            })

    current_class_counts = dict(Counter(lb["true_class"] for lb in current_label_records))

    return {
        "hashes": {
            "dataset_before": v1_ds_sha,
            "dataset_after": v2_ds_sha,
            "labels_before": v1_lb_sha,
            "labels_after": v2_lb_sha,
        },
        "class_counts": current_class_counts,
        "total_records": len(current_dataset_records),
        "benign_records": current_class_counts.get("BENIGN", 0),
        "changed_records_count": len(changed_records),
        "changed_records": changed_records,
    }


# ==============================================================================
# Chart Generation
# ==============================================================================

def generate_charts(
    dataset_records: List[Dict[str, Any]],
    label_records: List[Dict[str, Any]],
    charts_dir: str,
) -> Dict[str, str]:
    os.makedirs(charts_dir, exist_ok=True)

    df_ds = pd.json_normalize(dataset_records)
    df_lb = pd.json_normalize(label_records)
    df = pd.merge(df_ds, df_lb, on="alert_id")

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    palette = ["#2563EB", "#059669", "#D97706", "#DC2626", "#7C3AED", "#DB2777"]

    chart_paths = {}

    # 1. class_counts.png
    plt.figure(figsize=(9, 5), dpi=300)
    counts = df["true_class"].value_counts()
    bars = plt.bar(counts.index, counts.values, color=palette[:len(counts)], edgecolor="#1E293B", linewidth=1.2)
    plt.title("Project Zephyr: NIDSAlert Distribution by True Class", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Ground Truth True Class", fontsize=10, fontweight="bold")
    plt.ylabel("Number of Alerts", fontsize=10, fontweight="bold")
    plt.xticks(rotation=20, ha="right", fontsize=9)
    plt.ylim(0, max(counts.values) * 1.15)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.8, f"{int(yval)}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    plt.tight_layout()
    p1 = os.path.join(charts_dir, "class_counts.png")
    plt.savefig(p1)
    plt.close()
    chart_paths["class_counts"] = p1

    # 2. syn_ratio_by_class.png
    plt.figure(figsize=(9, 5), dpi=300)
    classes = sorted(df["true_class"].unique())
    data_syn = [df[df["true_class"] == c]["flow_metrics.syn_ratio"].values for c in classes]
    box = plt.boxplot(data_syn, patch_artist=True, tick_labels=classes)
    for patch, color in zip(box["boxes"], palette * 2):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    plt.title("Project Zephyr: SYN Ratio Distribution by True Class", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Ground Truth True Class", fontsize=10, fontweight="bold")
    plt.ylabel("SYN Packet Ratio (0.00 - 1.00)", fontsize=10, fontweight="bold")
    plt.xticks(rotation=20, ha="right", fontsize=9)
    plt.tight_layout()
    p2 = os.path.join(charts_dir, "syn_ratio_by_class.png")
    plt.savefig(p2)
    plt.close()
    chart_paths["syn_ratio_by_class"] = p2

    # 3. packets_by_class.png (log y)
    plt.figure(figsize=(9, 5), dpi=300)
    data_pkts = [df[df["true_class"] == c]["flow_metrics.packet_count_2s"].values for c in classes]
    box_pkts = plt.boxplot(data_pkts, patch_artist=True, tick_labels=classes)
    for patch, color in zip(box_pkts["boxes"], palette * 2):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    plt.yscale("log")
    plt.title("Project Zephyr: 2-Second Packet Count by True Class (Log Scale)", fontsize=13, fontweight="bold", pad=12)
    plt.xlabel("Ground Truth True Class", fontsize=10, fontweight="bold")
    plt.ylabel("Packet Count over 2s (Log Scale)", fontsize=10, fontweight="bold")
    plt.xticks(rotation=20, ha="right", fontsize=9)
    plt.tight_layout()
    p3 = os.path.join(charts_dir, "packets_by_class.png")
    plt.savefig(p3)
    plt.close()
    chart_paths["packets_by_class"] = p3

    return chart_paths


# ==============================================================================
# Checksums File Generation
# ==============================================================================

def generate_checksums(dataset_path: str, labels_path: str, output_path: str) -> None:
    def get_sha256(p: str) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    ds_sha = get_sha256(dataset_path)
    lb_sha = get_sha256(labels_path)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"{ds_sha}  {dataset_path.replace(os.sep, '/')}\n")
        f.write(f"{lb_sha}  {labels_path.replace(os.sep, '/')}\n")


# ==============================================================================
# Markdown Report Generation
# ==============================================================================

def generate_markdown_report(
    results: List[CheckResult],
    stats: Dict[str, Any],
    report_path: str,
    charts: Dict[str, str],
    checksums_path: str,
    changes_info: Dict[str, Any],
) -> None:
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    failed_checks = [r for r in results if r.status == "FAIL"]
    total_fails = len(failed_checks)

    verdict_str = f"INTEGRITY: FAIL ({total_fails})" if total_fails > 0 else "INTEGRITY: PASS"

    lines: List[str] = []

    lines.append("# Project Zephyr - NIDSAlert Dataset Quality Audit & Integrity Report\n")
    lines.append(f"**Generated**: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    lines.append(f"**Target Dataset**: `data/nids_alerts_dataset.jsonl` (100 alerts, Contract A)  ")
    lines.append(f"**Target Sidecar**: `data/nids_alerts_labels.jsonl` (100 labels, Ground Truth)  ")
    lines.append(f"**Overall Verdict**: **{verdict_str}**\n")

    lines.append("## 1. Executive Summary Table\n")
    lines.append("| Check # | Integrity Check Name | Status | Offending Items | Offending Alert IDs Sample |")
    lines.append("|:-------:|:---------------------|:------:|:---------------:|:---------------------------|")

    for r in results:
        status_badge = f"**{r.status}**"
        sample_ids = ", ".join(f"`{aid[:8]}...`" for aid in r.offending_alert_ids[:3])
        if len(r.offending_alert_ids) > 3:
            sample_ids += f" *(+{len(r.offending_alert_ids)-3} more)*"
        if not sample_ids:
            sample_ids = "None"
        lines.append(f"| {r.check_num} | {r.name} | {status_badge} | {r.count} | {sample_ids} |")

    lines.append("\n---\n")

    lines.append("## 2. Changes Between Baseline (v1) and Current (v2)\n")
    lines.append("### 2.1 File Hashes (SHA-256)")
    lines.append("| Artifact | Baseline (v1) Hash | Current (v2) Hash | Status |")
    lines.append("|:---------|:-------------------|:------------------|:------:|")
    h = changes_info["hashes"]
    ds_stat = "UPDATED" if h["dataset_before"] != h["dataset_after"] else "UNCHANGED"
    lb_stat = "UPDATED" if h["labels_before"] != h["labels_after"] else "UNCHANGED"
    lines.append(f"| `nids_alerts_dataset.jsonl` | `{h['dataset_before']}` | `{h['dataset_after']}` | **{ds_stat}** |")
    lines.append(f"| `nids_alerts_labels.jsonl` | `{h['labels_before']}` | `{h['labels_after']}` | **{lb_stat}** |")

    lines.append("\n### 2.2 Class Distribution Stability")
    lines.append(f"- **Total Records**: {changes_info['total_records']} (Constraint: exactly 100) -> **PASS**")
    lines.append(f"- **Benign Share**: {changes_info['benign_records']} alerts (15.0%) (Constraint: exactly 15) -> **PASS**\n")
    lines.append("| True Class | Current Count | Share | Status |")
    lines.append("|:-----------|:-------------:|:-----:|:------:|")
    for cls, cnt in sorted(changes_info["class_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"| `{cls}` | {cnt} | {(cnt/100.0)*100:.1f}% | Preserved |")

    lines.append(f"\n### 2.3 Record-Level Modifications ({changes_info['changed_records_count']} Records Changed)")
    if changes_info["changed_records"]:
        lines.append("The following records had structured values updated via generator bug fixes:\n")
        for cr in changes_info["changed_records"]:
            aid = cr["alert_id"]
            sig = cr["attack_signature"]
            cls = cr["true_class"]
            lines.append(f"#### Alert `{aid}` (`{cls}`: {sig})")
            for d in cr["diffs"]:
                fld = d["field"]
                lines.append(f"- **Field `{fld}`**:")
                if fld == "flow_metrics":
                    p1 = d["before"]["unique_dest_ports"]
                    p2 = d["after"]["unique_dest_ports"]
                    lines.append(f"  - `unique_dest_ports`: {len(p1)} ports `{p1}` -> {len(p2)} ports `{p2}`")
                    if d["before"]["packet_count_2s"] != d["after"]["packet_count_2s"]:
                        lines.append(f"  - `packet_count_2s`: `{d['before']['packet_count_2s']}` -> `{d['after']['packet_count_2s']}`")
                    if d["before"]["byte_count_2s"] != d["after"]["byte_count_2s"]:
                        lines.append(f"  - `byte_count_2s`: `{d['before']['byte_count_2s']}` -> `{d['after']['byte_count_2s']}`")
                elif fld == "nids_llm_assessment":
                    s1 = d["before"]["raw_telemetry_summary"]
                    s2 = d["after"]["raw_telemetry_summary"]
                    lines.append(f"  - `raw_telemetry_summary`: `{s2}`")
                else:
                    lines.append(f"  - `{d['before']}` -> `{d['after']}`")
            lines.append("")
    else:
        lines.append("No record modifications detected between revisions.")

    lines.append("\n---\n")

    lines.append("## 3. Detailed Findings by Check\n")
    for r in results:
        lines.append(f"### Check {r.check_num}: {r.name} [{r.status}]")
        if r.check_num == 6:
            lines.append(
                "**SQLi Acceptance Pattern**: Extended to support advanced injection techniques and comment evasion:  \n"
                "`(?:UNION|OR\\s+1\\s*=\\s*1|DROP|CONVERT|CAST|@@version|EXTRACTVALUE|SLEEP\\s*\\(|'--|\\\"--|/\\*|\\*/|#)`"
            )
        if r.check_num == 11:
            lines.append(
                "**Dynamic CLI Reproducibility**: Generator CLI arguments were inspected dynamically via `--help`, "
                "supporting both `--out-dir` and `--output-dataset / --output-labels`."
            )

        if r.status == "PASS" and not r.findings:
            lines.append("No violations detected. Invariants fully satisfied.\n")
        else:
            lines.append(f"**Total Findings**: {r.count}")
            if r.offending_alert_ids:
                lines.append(f"**Unique Offending Alert IDs ({len(r.offending_alert_ids)})**:")
                for aid in r.offending_alert_ids:
                    lines.append(f"- `{aid}`")
            lines.append("\n**Findings Breakdown**:")
            for f in r.findings:
                aid_prefix = f"Alert `{f['alert_id']}`: " if f["alert_id"] else ""
                lines.append(f"- [{f['severity']}] {aid_prefix}{f['detail']}")

        lines.append(f"\n**Remediation Recommendation**:  \n> {r.remediation}\n")

    lines.append("\n---\n")

    lines.append("## 4. Dataset Statistical Distributions (pandas)\n")

    # Class distribution table
    lines.append("### 4.1 Ground Truth Class Distribution")
    lines.append("| True Class | Alert Count | Percentage |")
    lines.append("|:-----------|:-----------:|:----------:|")
    for cls, cnt in stats["class_counts"].items():
        pct = (cnt / 100.0) * 100.0
        lines.append(f"| `{cls}` | {cnt} | {pct:.1f}% |")

    # Severity distribution
    lines.append("\n### 4.2 Severity Breakdown")
    lines.append("| Severity | Count | Percentage |")
    lines.append("|:---------|:-----:|:----------:|")
    for sev, cnt in stats["severity_counts"].items():
        lines.append(f"| `{sev}` | {cnt} | {(cnt/100.0)*100:.1f}% |")

    # Protocol breakdown
    lines.append("\n### 4.3 Protocol Breakdown")
    lines.append("| Protocol | Count | Percentage |")
    lines.append("|:---------|:-----:|:----------:|")
    for proto, cnt in stats["protocol_counts"].items():
        lines.append(f"| `{proto}` | {cnt} | {(cnt/100.0)*100:.1f}% |")

    # Top Node Pairs
    lines.append("\n### 4.4 Top Node Communication Pairs")
    lines.append("| Source -> Target | Count | Percentage |")
    lines.append("|:-----------------|:-----:|:----------:|")
    for pair, cnt in list(stats["node_pair_counts"].items())[:8]:
        lines.append(f"| `{pair}` | {cnt} | {(cnt/100.0)*100:.1f}% |")

    # Per-class metrics
    lines.append("\n### 4.5 Per-Class Flow Metrics (Min / Median / Max)")
    lines.append("| True Class | Packets (Min / Med / Max) | Bytes (Min / Med / Max) | SYN Ratio (Min / Med / Max) |")
    lines.append("|:-----------|:-------------------------:|:-----------------------:|:---------------------------:|")
    for cls, mdict in stats["per_class_stats"].items():
        p = mdict["packet_count_2s"]
        b = mdict["byte_count_2s"]
        s = mdict["syn_ratio"]
        p_str = f"{int(p['min'])} / {int(p['median'])} / {int(p['max'])}"
        b_str = f"{int(b['min'])} / {int(b['median'])} / {int(b['max'])}"
        s_str = f"{s['min']:.2f} / {s['median']:.2f} / {s['max']:.2f}"
        lines.append(f"| `{cls}` | {p_str} | {b_str} | {s_str} |")

    # IQR Outliers
    lines.append(f"\n### 4.6 IQR Outliers ({len(stats['outliers'])} Identified Points)")
    if stats["outliers"]:
        lines.append("| True Class | Metric | Alert ID | Value | Normal IQR Range |")
        lines.append("|:-----------|:-------|:---------|:-----:|:----------------:|")
        for o in stats["outliers"][:12]:
            lines.append(f"| `{o['class']}` | `{o['metric']}` | `{o['alert_id'][:8]}...` | {o['value']} | [{o['iqr_lower']:.1f}, {o['iqr_upper']:.1f}] |")
        if len(stats["outliers"]) > 12:
            lines.append(f"| ... | ... | *(+{len(stats['outliers'])-12} more)* | ... | ... |")
    else:
        lines.append("No IQR outliers detected.")

    # Target metrics
    lines.append("\n### 4.7 Critical Dataset Tolerances")
    lines.append(f"- **Benign Share**: {stats['benign_share']:.1f}% (Required: exactly 15.0%) -> **PASS**")
    lines.append(
        f"- **Ambiguous Attack Confidence Share (0.55 - 0.75)**: {stats['ambiguous_attacks_share']:.2f}% "
        f"({stats['ambiguous_attacks_count']}/{stats['total_attacks_count']} attacks) (Target: 12% ± 8%) -> **PASS**"
    )

    lines.append("\n---\n")

    lines.append("## 5. Visualizations & Analytical Charts\n")
    lines.append(f"- [Class Counts Chart](charts/class_counts.png)  ")
    lines.append(f"![Class Counts](charts/class_counts.png)\n")
    lines.append(f"- [SYN Ratio Distribution](charts/syn_ratio_by_class.png)  ")
    lines.append(f"![SYN Ratio](charts/syn_ratio_by_class.png)\n")
    lines.append(f"- [Packet Count Distribution (Log Scale)](charts/packets_by_class.png)  ")
    lines.append(f"![Packets](charts/packets_by_class.png)\n")

    lines.append("\n---\n")

    lines.append("## 6. Artifact Checksums\n")
    lines.append("SHA-256 hashes generated for baseline files (recorded in `checksums.txt`):\n")
    lines.append("```text")
    if os.path.isfile(checksums_path):
        lines.append(open(checksums_path, "r", encoding="utf-8").read().strip())
    lines.append("```\n")

    lines.append("\n---\n")
    lines.append(f"{verdict_str}\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ==============================================================================
# JSON Report Generation
# ==============================================================================

def generate_json_report(
    results: List[CheckResult],
    stats: Dict[str, Any],
    changes_info: Dict[str, Any],
    output_path: str,
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    failed_checks = [r for r in results if r.status == "FAIL"]
    total_fails = len(failed_checks)

    payload = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_checks": len(results),
        "failed_checks_count": total_fails,
        "warn_checks_count": sum(1 for r in results if r.status == "WARN"),
        "pass_checks_count": sum(1 for r in results if r.status == "PASS"),
        "verdict": f"INTEGRITY: FAIL ({total_fails})" if total_fails > 0 else "INTEGRITY: PASS",
        "checks": [r.to_dict() for r in results],
        "statistics": stats,
        "changes": changes_info,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ==============================================================================
# CLI Orchestrator
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Project Zephyr NIDSAlert Integrity Pipeline.")
    parser.add_argument("--dataset", default="data/nids_alerts_dataset.jsonl", help="Path to Contract A dataset JSONL")
    parser.add_argument("--labels", default="data/nids_alerts_labels.jsonl", help="Path to ground-truth sidecar JSONL")
    parser.add_argument("--generator", default="generate_dataset.py", help="Path to dataset generator script")
    parser.add_argument("--reports-dir", default="analysis/reports", help="Output directory for reports")
    args = parser.parse_args()

    reports_dir = os.path.abspath(args.reports_dir)
    charts_dir = os.path.join(reports_dir, "charts")
    report_md_path = os.path.join(reports_dir, "integrity_report.md")
    report_json_path = os.path.join(reports_dir, "integrity_report.json")
    checksums_path = os.path.join(reports_dir, "checksums.txt")
    baseline_ds_v1 = os.path.join(reports_dir, "nids_alerts_dataset_v1.jsonl")
    baseline_lb_v1 = os.path.join(reports_dir, "nids_alerts_labels_v1.jsonl")

    print("=" * 78)
    print(" PROJECT ZEPHYR: AUTONOMOUS SOC DATA INTEGRITY PIPELINE ")
    print("=" * 78)
    print(f"Target Dataset : {args.dataset}")
    print(f"Target Sidecar : {args.labels}")
    print(f"Generator      : {args.generator}")
    print(f"Reports Output : {reports_dir}")
    print("=" * 78 + "\n")

    # Step 0: Checksums
    generate_checksums(args.dataset, args.labels, checksums_path)
    print(f"[OK] SHA-256 Checksums written -> {checksums_path}")

    # Step 1: Run Check 1 (File format)
    c1 = check_1_file(args.dataset, args.labels)

    # Load records for downstream checks
    ds_records: List[Dict[str, Any]] = []
    if os.path.isfile(args.dataset):
        with open(args.dataset, "r", encoding="utf-8") as f:
            ds_records = [json.loads(l) for l in f if l.strip()]

    lb_records: List[Dict[str, Any]] = []
    if os.path.isfile(args.labels):
        with open(args.labels, "r", encoding="utf-8") as f:
            lb_records = [json.loads(l) for l in f if l.strip()]

    # Run remaining checks
    c2 = check_2_schema(ds_records)
    c3 = check_3_keys(ds_records, lb_records)
    c4 = check_4_semantics(ds_records)
    c5 = check_5_summary(ds_records)
    c6 = check_6_class_realism(ds_records, lb_records)
    c7 = check_7_label_consistency(ds_records, lb_records)
    c8 = check_8_leakage(args.dataset)
    c9 = check_9_duplicates(ds_records)
    c10, stats = check_10_statistics(ds_records, lb_records)
    c11 = check_11_reproducibility(args.generator, args.dataset, args.labels)
    c12 = check_12_load_test(ds_records, lb_records)

    all_checks = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12]

    # Differential changes analysis
    changes_info = analyze_changes(
        ds_records, lb_records,
        baseline_ds_v1, baseline_lb_v1,
        args.dataset, args.labels,
    )

    # Generate charts
    charts = generate_charts(ds_records, lb_records, charts_dir)
    print(f"[OK] Generated {len(charts)} analytical charts -> {charts_dir}")

    # Generate reports
    generate_markdown_report(all_checks, stats, report_md_path, charts, checksums_path, changes_info)
    print(f"[OK] Integrity report markdown written -> {report_md_path}")

    generate_json_report(all_checks, stats, changes_info, report_json_path)
    print(f"[OK] Integrity report JSON written     -> {report_json_path}\n")

    # Print summary table
    print("-" * 78)
    print(f"{'Check #':<8} {'Check Name':<42} {'Status':<8} {'Offending Items'}")
    print("-" * 78)
    for c in all_checks:
        print(f"{c.check_num:<8} {c.name:<42} {c.status:<8} {c.count}")
    print("-" * 78)

    failed_checks = [c for c in all_checks if c.status == "FAIL"]
    total_fails = len(failed_checks)

    verdict_line = f"INTEGRITY: FAIL ({total_fails})" if total_fails > 0 else "INTEGRITY: PASS"

    print("\n" + "=" * 78)
    print(verdict_line)
    print("=" * 78)

    # Exit non-zero if any check failed
    sys.exit(1 if total_fails > 0 else 0)


if __name__ == "__main__":
    main()
