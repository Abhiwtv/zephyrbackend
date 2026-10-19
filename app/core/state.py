import operator
from typing import List, Annotated, Sequence, Literal, Dict, Any, Optional
from pydantic import BaseModel, Field, AliasChoices, ConfigDict, field_validator
from langchain_core.messages import BaseMessage

# =====================================================================
# CANONICAL TOPOLOGY CONSTANTS (br-zephyr: 172.28.0.11 - 172.28.0.15)
# =====================================================================

ValidNode = Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]

NODE_IP_MAP: Dict[str, str] = {
    "pc-1": "172.28.0.11",
    "pc-2": "172.28.0.12",
    "pc-3": "172.28.0.13",
    "pc-4": "172.28.0.14",
    "pc-5": "172.28.0.15",
}

IP_NODE_MAP: Dict[str, str] = {v: k for k, v in NODE_IP_MAP.items()}


def _normalize_node_name(value: Any) -> Any:
    """
    Normalizes accidental Cyrillic 'р' (\u0440) and 'с' (\u0441) characters
    from PDF copy-pastes into standard ASCII 'p' and 'c'.
    """
    if isinstance(value, str):
        return value.replace("\u0440", "p").replace("\u0441", "c").strip()
    return value


# =====================================================================
# CONTRACT A: NIDSAlert (Sensor & Training Dataset Schema)
# =====================================================================

class FlowMetrics(BaseModel):
    packet_count_2s: int = Field(
        ge=1,
        description="Total packets observed in the 2-second sliding window"
    )
    byte_count_2s: int = Field(
        ge=64,
        description="Total bytes transferred in the window"
    )
    syn_ratio: float = Field(
        ge=0.0,
        le=1.0,
        description="Ratio of SYN flags set in TCP headers"
    )
    unique_dest_ports: List[int] = Field(
        description="List of ports targeted during the anomaly window"
    )
    payload_sample: str = Field(
        description="Raw ASCII/Hex truncated sample of the suspicious packet payload"
    )


class NIDSAssessment(BaseModel):
    attack_signature: str = Field(
        description="Human-readable attack classification name"
    )
    mitre_tactic: str = Field(
        description="MITRE ATT&CK tactic category (e.g., Initial Access, Impact)"
    )
    mitre_technique_id: str = Field(
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Standard MITRE technique ID"
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Model confidence in threat identification"
    )
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    raw_telemetry_summary: str = Field(
        description="Verbose explanation of why the flow was flagged"
    )


class NIDSAlert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    alert_id: str = Field(
        description="Unique UUID or event hash for tracing"
    )
    timestamp: str = Field(
        description="ISO-8601 UTC timestamp of detection"
    )
    source_node: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    source_ip: str = Field(pattern=r"^172\.28\.0\.1[1-5]$")
    target_node: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    target_ip: str = Field(pattern=r"^172\.28\.0\.1[1-5]$")
    dest_port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "HTTP"]
    flow_metrics: FlowMetrics
    nids_llm_assessment: NIDSAssessment = Field(
        validation_alias=AliasChoices("nids_llm_assessment", "nids_Ilm_assessment"),
        description="Semantic assessment produced by the NIDS Sensor LLM"
    )

    @field_validator("source_node", "target_node", mode="before")
    @classmethod
    def normalize_nodes(cls, v: Any) -> Any:
        return _normalize_node_name(v)


# =====================================================================
# CONTRACT B: MitigationEnvelope (Responder, Training & Audit Schema)
# =====================================================================

class ActionPayload(BaseModel):
    action_type: Literal[
        "BLOCK_SOURCE_IP",
        "DROP_PORT_TRAFFIC",
        "RATE_LIMIT_SYN",
        "ISOLATE_NODE",
        "NO_OP"
    ]
    target_container: Literal["pc-1", "pc-2", "pc-3", "pc-4", "pc-5"]
    source_ip: str = Field(pattern=r"^172\.28\.0\.1[1-5]$")
    dest_port: int = Field(ge=1, le=65535)
    iptables_cmd: str = Field(
        description="Exact executable shell command executed inside the container namespace"
    )
    estimated_collateral_impact: Literal["ZERO", "LOW", "MODERATE", "HIGH"]

    @field_validator("target_container", mode="before")
    @classmethod
    def normalize_container(cls, v: Any) -> Any:
        return _normalize_node_name(v)


class ExecutionAudit(BaseModel):
    executed_successfully: bool = Field(default=False)
    exit_code: int = Field(default=-1)
    stdout_stderr: Optional[str] = Field(default=None)
    post_mitigation_packet_drop_verified: bool = Field(
        default=False,
        description="True if subsequent attack packets dropped to 0"
    )


class GRPORewardBreakdown(BaseModel):
    schema_compliance_score: float = Field(
        ge=-2.0,
        le=2.0,
        description="Reward component for valid JSON & Pydantic parse"
    )
    entity_grounding_score: float = Field(
        ge=-3.0,
        le=3.0,
        description="Reward component for matching IPs/ports in alert"
    )
    surgical_precision_score: float = Field(
        ge=-3.0,
        le=3.0,
        description="Reward component for optimal least-privilege blocking"
    )
    total_reward: float = Field(ge=-8.0, le=8.0)


class MitigationEnvelope(BaseModel):
    threat_classification: Literal[
        "SYN_FLOOD",
        "RCE_ATTEMPT",
        "SQL_INJECTION",
        "SSH_BRUTE_FORCE",
        "PORT_SCAN",
        "BENIGN"
    ]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    reasoning_trace: str = Field(
        description="Step-by-step security reasoning leading to the chosen action"
    )
    chosen_mitigation: ActionPayload
    rejected_alternative: ActionPayload
    rejection_reason: str = Field(
        description="Why the alternative action was sub-optimal or dangerous"
    )
    execution_audit: Optional[ExecutionAudit] = Field(
        default=None,
        description="Filled in live by FastAPI after running the command"
    )
    grpo_scoring_debug: Optional[GRPORewardBreakdown] = Field(
        default=None,
        description="Filled in by deterministic GRPO reward evaluator"
    )


# =====================================================================
# LEGACY LANGGRAPH STATE (Preserved for Backward Compatibility)
# =====================================================================

class IncidentState(BaseModel):
    """
    The unified state object that is passed between all LangGraph nodes.
    Acts as the complete contextual memory for a single attack simulation.
    """
    # --- Core Identifiers ---
    incident_id: str = Field(description="Unique tracking ID for the alert")
    status: Literal[
        "ALERT_RECEIVED",
        "INTAKE",
        "INVESTIGATING",
        "EVIDENCE_PLANNING",
        "ASSESSING",
        "DEFENDING",
        "REVIEWING",
        "EXECUTING",
        "VERIFYING",
        "ADAPTING",
        "COMPLETED",
        "FAILED"
    ] = Field(default="ALERT_RECEIVED", description="Current node phase")

    # --- Alert Context ---
    alert_signature: str = Field(default="", description="e.g., CVE-2021-44228 JNDI RCE")
    source_ip: str = Field(default="", description="Attacker IP")
    target_ip: str = Field(default="", description="Victim IP or internal asset")

    # --- New Contract Payloads (Optional for hybrid LangGraph compatibility) ---
    nids_alert: Optional[NIDSAlert] = Field(default=None, description="Validated Contract A payload")
    mitigation_envelope: Optional[MitigationEnvelope] = Field(default=None, description="Validated Contract B payload")

    # --- Investigator & Strategist Artifacts ---
    hypotheses: List[str] = Field(default_factory=list, description="Theories about the attack success")
    evidence_gathered: List[str] = Field(default_factory=list, description="Raw logs or tool outputs")
    missing_evidence: List[str] = Field(default_factory=list, description="Forensic gaps identified")

    # --- Assessor Artifacts ---
    assessment_outcome: str = Field(default="", description="ATTACK_SUCCEEDED or ATTACK_FAILED")
    confidence: float = Field(default=0.0, description="Mathematical certainty of the assessment")
    assessment_justification: str = Field(default="", description="Reasoning for the outcome")

    # --- Two-Phase Retrieval (RAG) Memory ---
    textbook_playbook: str = Field(default="", description="Phase 1: Baseline textbook SOC SOP")
    historical_context: str = Field(default="", description="Phase 2: RART-generated past mistakes (Overrides Phase 1)")

    # --- Defense Node Proposals ---
    proposed_action: str = Field(default="", description="The exact mitigation (e.g., BLOCK_SOURCE, ISOLATE_ASSET)")
    proposed_target: str = Field(default="", description="The infrastructure target of the action")
    action_justification: str = Field(default="", description="LLM reasoning for choosing this action")

    # --- Reviewer Simulation (The Guardrail) ---
    reviewer_decision: Literal["APPROVE", "REJECT", "PENDING"] = Field(default="PENDING")
    reviewer_feedback: str = Field(default="", description="Feedback passed back to Defense if rejected")
    simulated_blast_radius: str = Field(default="", description="Calculated infrastructure damage if executed")

    # --- RART (Policy Mutation) ---
    learned_rule: str = Field(default="", description="The compressed semantic rule generated from a near-miss")

    # --- Final Execution ---
    execution_result: str = Field(default="", description="Result from pushing the action to the network fabric")
    verification_result: str = Field(default="", description="Validation that traffic stabilized")
    judge_scorecard: Dict[str, Any] = Field(default_factory=dict, description="Hackathon evaluation metrics")

    # --- LangChain Message History ---
    messages: Annotated[Sequence[BaseMessage], operator.add] = Field(default_factory=list)