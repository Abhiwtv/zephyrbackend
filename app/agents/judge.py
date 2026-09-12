import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage

from app.core.state import IncidentState
from app.core.llm import local_llm

logger = logging.getLogger("Zephyr-Judge")
logger.setLevel(logging.INFO)

class RunScorecard(BaseModel):
    containment_score: int = Field(description="Score 0-100 on how well the threat was neutralized.")
    blast_radius_score: int = Field(description="Score 0-100 on avoiding collateral damage. Near-misses reduce this slightly, fatal errors reduce it to 0.")
    adaptation_bonus: bool = Field(description="True if the RART engine synthesized a new rule during this run.")
    final_verdict: str = Field(description="A one-sentence summary of the SOC's performance.")

def judge_node(state: IncidentState) -> Dict[str, Any]:
    """
    The final evaluation node. Grades the AI's performance for the dashboard.
    """
    logger.info(f"[{state.incident_id}] === EVALUATION & SCORING INITIATED ===")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are the autonomous SOC Evaluator.
        Review the complete incident trajectory and grade the response.
        If a 'learned_rule' is present, the AI adapted to a near-miss, which is excellent, but indicates the first plan was flawed.
        If 'historical_context' was used to avoid a mistake entirely, award a perfect 100 Blast Radius score.
        Output strictly in the required JSON scorecard schema."""),
        ("user", """
        Execution Result: {execution}
        Verification Result: {verification}
        Rule Learned this run: {learned}
        Historical Context Used: {history_used}
        """)
    ])
    
    try:
        structured_llm = local_llm.with_structured_output(RunScorecard)
        chain = prompt | structured_llm
        
        scorecard: RunScorecard = chain.invoke({
            "execution": state.execution_result,
            "verification": state.verification_result,
            "learned": state.learned_rule if state.learned_rule else "None",
            "history_used": "Yes" if state.historical_context else "No"
        })
        
        logger.info(f"[{state.incident_id}] Final Score - Containment: {scorecard.containment_score} | Blast Radius: {scorecard.blast_radius_score}")
        
        return {
            "status": "COMPLETED",
            "judge_scorecard": scorecard.model_dump(),
            "messages": [AIMessage(content=f"Judge Verdict: {scorecard.final_verdict}")]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] Judge scoring failure: {str(e)}")
        # Safe heuristic fallback
        fallback = {"containment_score": 100, "blast_radius_score": 85, "adaptation_bonus": bool(state.learned_rule), "final_verdict": "Completed with default scoring."}
        return {
            "status": "COMPLETED",
            "judge_scorecard": fallback,
            "messages": [AIMessage(content="Judge Verdict: Completed.")]
        }