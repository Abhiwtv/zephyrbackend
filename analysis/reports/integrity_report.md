# Project Zephyr - NIDSAlert Dataset Quality Audit & Integrity Report

**Generated**: 2026-10-19 13:58:23 UTC  
**Target Dataset**: `data/nids_alerts_dataset.jsonl` (100 alerts, Contract A)  
**Target Sidecar**: `data/nids_alerts_labels.jsonl` (100 labels, Ground Truth)  
**Overall Verdict**: **INTEGRITY: PASS**

## 1. Executive Summary Table

| Check # | Integrity Check Name | Status | Offending Items | Offending Alert IDs Sample |
|:-------:|:---------------------|:------:|:---------------:|:---------------------------|
| 1 | File Formatting & Encoding | **PASS** | 0 | None |
| 2 | Strict Schema Validation (Contract A) | **PASS** | 0 | None |
| 3 | Key Integrity & 1:1 Sidecar Join | **PASS** | 0 | None |
| 4 | Semantic Invariants & Boundary Constraints | **PASS** | 0 | None |
| 5 | Raw Telemetry Summary Consistency | **PASS** | 0 | None |
| 6 | Class Realism & Domain Profile Verification | **PASS** | 0 | None |
| 7 | Ground-Truth Label & Metadata Consistency | **PASS** | 0 | None |
| 8 | Label & Original Topology Leakage | **PASS** | 0 | None |
| 9 | Exact & Near-Duplicate Detection | **PASS** | 0 | None |
| 10 | Statistical Distribution & Outlier Analysis | **PASS** | 0 | None |
| 11 | Deterministic Generator Reproducibility | **PASS** | 0 | None |
| 12 | Dataframe Ingestion & Missing Value Load Test | **PASS** | 0 | None |

---

## 2. Changes Between Baseline (v1) and Current (v2)

### 2.1 File Hashes (SHA-256)
| Artifact | Baseline (v1) Hash | Current (v2) Hash | Status |
|:---------|:-------------------|:------------------|:------:|
| `nids_alerts_dataset.jsonl` | `282620e8bedfa90071845a2b5a88ed07f20b3addfe622786865c71ac1dfb77b1` | `200947270d288738d6b768092ea8e86213de22e348b23901997d86739ee83d07` | **UPDATED** |
| `nids_alerts_labels.jsonl` | `671a25bd5b7ab0a00b1b3613213c3f1b998615f83276f407038ddcc90fb239f3` | `671a25bd5b7ab0a00b1b3613213c3f1b998615f83276f407038ddcc90fb239f3` | **UNCHANGED** |

### 2.2 Class Distribution Stability
- **Total Records**: 100 (Constraint: exactly 100) -> **PASS**
- **Benign Share**: 15 alerts (15.0%) (Constraint: exactly 15) -> **PASS**

| True Class | Current Count | Share | Status |
|:-----------|:-------------:|:-----:|:------:|
| `SYN_FLOOD` | 33 | 33.0% | Preserved |
| `SSH_BRUTE_FORCE` | 17 | 17.0% | Preserved |
| `RCE_ATTEMPT` | 16 | 16.0% | Preserved |
| `BENIGN` | 15 | 15.0% | Preserved |
| `SQL_INJECTION` | 10 | 10.0% | Preserved |
| `PORT_SCAN` | 9 | 9.0% | Preserved |

### 2.3 Record-Level Modifications (13 Records Changed)
The following records had structured values updated via generator bug fixes:

#### Alert `d1843324-17e8-492a-95ce-e5db9e87e04c` (`SYN_FLOOD`: NIDS: DoS Slowloris Incomplete HTTP Header Exhaustion)
- **Field `protocol`**:
  - `TCP` -> `HTTP`

#### Alert `a2086977-a9f2-4336-83f4-a9a948a639d0` (`SYN_FLOOD`: NIDS: DoS Slowloris Incomplete HTTP Header Exhaustion)
- **Field `protocol`**:
  - `TCP` -> `HTTP`

#### Alert `b4d7e28e-271e-4ee2-b1a6-b1f1620e99d3` (`PORT_SCAN`: NIDS: Internal Reconnaissance Port Scan from Compromised Host)
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 6 ports `[21, 22, 80, 139, 445, 3389]` -> 20 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 458 packets (26564 bytes) over 2s with syn_ratio 0.97 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]: Compromised internal workstation probing core subnet infrastructure ports.`

#### Alert `8bcf53a1-bc10-4a52-bf5d-2fdf89c8d2ab` (`PORT_SCAN`: NIDS: Nmap UDP Service Discovery Scan (sU))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[53, 67, 123, 161, 500]` -> 20 ports `[53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 386 packets (24704 bytes) over 2s with syn_ratio 0.00 targeting ports [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]: Nmap scanner profiling destination ports using sU signature.`

#### Alert `da7b9095-63d6-4a39-80e3-befd4c71e0fe` (`PORT_SCAN`: NIDS: Nmap TCP Xmas Tree Probe (sX - FIN/PSH/URG))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[21, 22, 80, 443, 8080]` -> 24 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 228 packets (12996 bytes) over 2s with syn_ratio 0.00 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]: Nmap scanner profiling destination ports using sX signature.`

#### Alert `6160a6b4-9360-415f-83fe-0183e172b725` (`PORT_SCAN`: NIDS: Nmap Full TCP Connect Scan (sT))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[21, 22, 80, 443, 8080]` -> 24 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 428 packets (25680 bytes) over 2s with syn_ratio 0.40 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]: Nmap scanner profiling destination ports using sT signature.`

#### Alert `6b44fa8d-d5f2-4073-b414-02b1e4429ebb` (`PORT_SCAN`: NIDS: Nmap TCP Null Probe (sN - No Flags))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[21, 22, 80, 443, 8080]` -> 24 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 419 packets (23045 bytes) over 2s with syn_ratio 0.00 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]: Nmap scanner profiling destination ports using sN signature.`

#### Alert `68586eba-6a34-4854-9071-4d5136c59dac` (`PORT_SCAN`: NIDS: Internal Reconnaissance Port Scan from Compromised Host)
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 6 ports `[21, 22, 80, 139, 445, 3389]` -> 20 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 509 packets (29013 bytes) over 2s with syn_ratio 0.99 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]: Compromised internal workstation probing core subnet infrastructure ports.`

#### Alert `560c95ee-638c-454c-876e-2bba7c5308bf` (`SYN_FLOOD`: NIDS: Distributed SYN Flood Attack (LOIT))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 1 ports `[80]` -> 1 ports `[80]`
  - `packet_count_2s`: `8008` -> `4302`
  - `byte_count_2s`: `440440` -> `232308`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 4302 packets (232308 bytes) over 2s with syn_ratio 0.95 targeting dest_port 80: Massive synchronized TCP SYN packet flood overwhelming network backlog.`

#### Alert `3b33f3d8-269c-4696-a36c-7b8714a0bccb` (`PORT_SCAN`: NIDS: Internal Reconnaissance Port Scan from Compromised Host)
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 6 ports `[21, 22, 80, 139, 445, 3389]` -> 20 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 631 packets (34705 bytes) over 2s with syn_ratio 0.94 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 8080]: Compromised internal workstation probing core subnet infrastructure ports.`

#### Alert `ac3c5640-3c20-492f-804a-96c4f3b63fe1` (`SYN_FLOOD`: NIDS: DoS Slowloris Incomplete HTTP Header Exhaustion)
- **Field `protocol`**:
  - `TCP` -> `HTTP`

#### Alert `db52ca58-0500-4bc6-b20d-cb6ef2311f17` (`PORT_SCAN`: NIDS: Nmap TCP SYN Stealth Scan (sS))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[21, 22, 80, 443, 8080]` -> 24 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 196 packets (12544 bytes) over 2s with syn_ratio 0.92 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]: Nmap scanner profiling destination ports using sS signature.`

#### Alert `5a0cdd7c-f157-4470-8182-67c47a1b5806` (`PORT_SCAN`: NIDS: Nmap TCP FIN Stealth Probe (sF))
- **Field `flow_metrics`**:
  - `unique_dest_ports`: 5 ports `[21, 22, 80, 443, 8080]` -> 24 ports `[21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]`
- **Field `nids_llm_assessment`**:
  - `raw_telemetry_summary`: `Observed 422 packets (25742 bytes) over 2s with syn_ratio 0.00 targeting ports [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888]: Nmap scanner profiling destination ports using sF signature.`


---

## 3. Detailed Findings by Check

### Check 1: File Formatting & Encoding [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. File conforms strictly to UTF-8, 100 non-empty lines, valid JSON.

### Check 2: Strict Schema Validation (Contract A) [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. All 100 alerts adhere strictly to Contract A schema with extra='forbid'.

### Check 3: Key Integrity & 1:1 Sidecar Join [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. All alert_ids are unique, valid UUID4s with perfect 1:1 join.

### Check 4: Semantic Invariants & Boundary Constraints [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. All semantic rules and physical boundaries are honored.

### Check 5: Raw Telemetry Summary Consistency [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Summary metrics and narrative protocol state match structured fields exactly.

### Check 6: Class Realism & Domain Profile Verification [PASS]
**SQLi Acceptance Pattern**: Extended to support advanced injection techniques and comment evasion:  
`(?:UNION|OR\s+1\s*=\s*1|DROP|CONVERT|CAST|@@version|EXTRACTVALUE|SLEEP\s*\(|'--|\"--|/\*|\*/|#)`
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. All class realism constraints satisfied across all attack signatures.

### Check 7: Ground-Truth Label & Metadata Consistency [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Exact label consistency, equivalence invariants, and hard negative count verified.

### Check 8: Label & Original Topology Leakage [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Clean separation between Contract A telemetry and sidecar labels.

### Check 9: Exact & Near-Duplicate Detection [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Zero exact or near-duplicate records identified.

### Check 10: Statistical Distribution & Outlier Analysis [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Statistical distribution conforms to all specified tolerances.

### Check 11: Deterministic Generator Reproducibility [PASS]
**Dynamic CLI Reproducibility**: Generator CLI arguments were inspected dynamically via `--help`, supporting both `--out-dir` and `--output-dataset / --output-labels`.
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Generator reproduced identical SHA-256 hashes via detected CLI mode '--out-dir'.

### Check 12: Dataframe Ingestion & Missing Value Load Test [PASS]
No violations detected. Invariants fully satisfied.


**Remediation Recommendation**:  
> None required. Dataframe flattens with zero NaNs across all 30 structured attributes.


---

## 4. Dataset Statistical Distributions (pandas)

### 4.1 Ground Truth Class Distribution
| True Class | Alert Count | Percentage |
|:-----------|:-----------:|:----------:|
| `SYN_FLOOD` | 33 | 33.0% |
| `SSH_BRUTE_FORCE` | 17 | 17.0% |
| `RCE_ATTEMPT` | 16 | 16.0% |
| `BENIGN` | 15 | 15.0% |
| `SQL_INJECTION` | 10 | 10.0% |
| `PORT_SCAN` | 9 | 9.0% |

### 4.2 Severity Breakdown
| Severity | Count | Percentage |
|:---------|:-----:|:----------:|
| `HIGH` | 37 | 37.0% |
| `CRITICAL` | 31 | 31.0% |
| `MEDIUM` | 17 | 17.0% |
| `LOW` | 15 | 15.0% |

### 4.3 Protocol Breakdown
| Protocol | Count | Percentage |
|:---------|:-----:|:----------:|
| `TCP` | 49 | 49.0% |
| `HTTP` | 43 | 43.0% |
| `UDP` | 7 | 7.0% |
| `ICMP` | 1 | 1.0% |

### 4.4 Top Node Communication Pairs
| Source -> Target | Count | Percentage |
|:-----------------|:-----:|:----------:|
| `pc-2 -> pc-4` | 45 | 45.0% |
| `pc-2 -> pc-3` | 15 | 15.0% |
| `pc-1 -> pc-4` | 10 | 10.0% |
| `pc-1 -> pc-3` | 6 | 6.0% |
| `pc-2 -> pc-1` | 6 | 6.0% |
| `pc-1 -> pc-2` | 5 | 5.0% |
| `pc-3 -> pc-4` | 4 | 4.0% |
| `pc-1 -> pc-5` | 4 | 4.0% |

### 4.5 Per-Class Flow Metrics (Min / Median / Max)
| True Class | Packets (Min / Med / Max) | Bytes (Min / Med / Max) | SYN Ratio (Min / Med / Max) |
|:-----------|:-------------------------:|:-----------------------:|:---------------------------:|
| `BENIGN` | 7 / 33 / 2762 | 511 / 14427 / 2344866 | 0.00 / 0.04 / 0.06 |
| `PORT_SCAN` | 196 / 422 / 631 | 12544 / 25680 / 34705 | 0.00 / 0.40 / 0.99 |
| `RCE_ATTEMPT` | 57 / 113 / 203 | 22230 / 34093 / 74095 | 0.05 / 0.08 / 0.15 |
| `SQL_INJECTION` | 35 / 54 / 95 | 15890 / 24888 / 45600 | 0.04 / 0.08 / 0.09 |
| `SSH_BRUTE_FORCE` | 48 / 87 / 151 | 4080 / 8930 / 48018 | 0.13 / 0.19 / 0.25 |
| `SYN_FLOOD` | 170 / 2500 / 7289 | 11033 / 752458 / 2855475 | 0.00 / 0.04 / 0.97 |

### 4.6 IQR Outliers (21 Identified Points)
| True Class | Metric | Alert ID | Value | Normal IQR Range |
|:-----------|:-------|:---------|:-----:|:----------------:|
| `BENIGN` | `packet_count_2s` | `d9d80b8d...` | 2762.0 | [-38.5, 113.5] |
| `BENIGN` | `packet_count_2s` | `76f72255...` | 1407.0 | [-38.5, 113.5] |
| `BENIGN` | `packet_count_2s` | `89c5b31a...` | 1842.0 | [-38.5, 113.5] |
| `BENIGN` | `byte_count_2s` | `d9d80b8d...` | 1861588.0 | [-50933.8, 92428.2] |
| `BENIGN` | `byte_count_2s` | `76f72255...` | 1743273.0 | [-50933.8, 92428.2] |
| `BENIGN` | `byte_count_2s` | `89c5b31a...` | 2344866.0 | [-50933.8, 92428.2] |
| `SYN_FLOOD` | `syn_ratio` | `6f92f25e...` | 0.97 | [-0.0, 0.1] |
| `SYN_FLOOD` | `syn_ratio` | `3875394c...` | 0.92 | [-0.0, 0.1] |
| `SYN_FLOOD` | `syn_ratio` | `560c95ee...` | 0.95 | [-0.0, 0.1] |
| `SYN_FLOOD` | `syn_ratio` | `67814c1f...` | 0.9 | [-0.0, 0.1] |
| `RCE_ATTEMPT` | `byte_count_2s` | `a07295e9...` | 74095.0 | [1797.8, 67681.8] |
| `SSH_BRUTE_FORCE` | `byte_count_2s` | `986f9025...` | 37605.0 | [-6172.5, 28503.5] |
| ... | ... | *(+9 more)* | ... | ... |

### 4.7 Critical Dataset Tolerances
- **Benign Share**: 15.0% (Required: exactly 15.0%) -> **PASS**
- **Ambiguous Attack Confidence Share (0.55 - 0.75)**: 10.59% (9/85 attacks) (Target: 12% ± 8%) -> **PASS**

---

## 5. Visualizations & Analytical Charts

- [Class Counts Chart](charts/class_counts.png)  
![Class Counts](charts/class_counts.png)

- [SYN Ratio Distribution](charts/syn_ratio_by_class.png)  
![SYN Ratio](charts/syn_ratio_by_class.png)

- [Packet Count Distribution (Log Scale)](charts/packets_by_class.png)  
![Packets](charts/packets_by_class.png)


---

## 6. Artifact Checksums

SHA-256 hashes generated for baseline files (recorded in `checksums.txt`):

```text
200947270d288738d6b768092ea8e86213de22e348b23901997d86739ee83d07  data/nids_alerts_dataset.jsonl
671a25bd5b7ab0a00b1b3613213c3f1b998615f83276f407038ddcc90fb239f3  data/nids_alerts_labels.jsonl
```


---

INTEGRITY: PASS
