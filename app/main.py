import os
import json
import asyncio
import logging
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Note: This import will resolve fully once we generate Batch 6 (orchestrator.py)
from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

# Configure robust console logging for backend visibility
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("Zephyr-API")

app = FastAPI(
    title="Zephyr Autonomous SOC Backend",
    description="Live inference API with SSE streaming for frontend telemetry visualization.",
    version="1.0.0"
)

# Standard CORS for Next.js / React frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AttackSimulationRequest(BaseModel):
    incident_id: str = Field(default="INC-LIVE-DEMO", description="Unique ID for this run")
    signature: str = Field(default="CVE-2021-44228 JNDI RCE", description="The IDS alert signature")
    source_ip: str = Field(default="104.28.15.12", description="The attacker's origin IP")
    target_ip: str = Field(default="10.0.1.15", description="The victim internal IP")

@app.get("/")
async def health_check():
    """Simple health check endpoint for deployment probes."""
    return {"status": "Zephyr SOC Backend is Online", "version": "1.0.0"}

@app.post("/api/simulate-attack/stream")
async def stream_incident_response(request: AttackSimulationRequest):
    """
    Server-Sent Events (SSE) Endpoint.
    Streams real-time LangGraph node execution states to the frontend.
    """
    logger.info(f"Incoming attack simulation request: {request.incident_id} from {request.source_ip}")
    
    # Initialize the rich state model
    initial_state = IncidentState(
        incident_id=request.incident_id,
        alert_signature=request.signature,
        source_ip=request.source_ip,
        target_ip=request.target_ip
    )

    async def event_generator():
        # 1. Connection Event
        init_payload = {
            "node": "system",
            "status": "connected",
            "message": "Initializing Zephyr Defense Matrix..."
        }
        yield f"data: {json.dumps(init_payload)}\n\n"
        await asyncio.sleep(0.5)

        try:
            # 2. Asynchronous Graph Execution Stream (LangChain v2 API)
            async for event in soc_graph.astream_events(initial_state, version="v2"):
                kind = event["event"]
                node_name = event.get("name", "unknown")
                
                # We filter specifically for node completions to provide clean UI updates
                if kind == "on_chain_end" and node_name not in ["LangGraph", "system"]:
                    
                    # Extract the dictionary of state mutations emitted by this node
                    output_data = event.get("data", {}).get("output", {})
                    if not isinstance(output_data, dict):
                        continue
                        
                    # Build a highly verbose payload for the UI
                    payload = {
                        "node": node_name,
                        "status": "completed",
                        "internal_status_flag": output_data.get("status", "PROCESSING"),
                        "action_proposed": output_data.get("proposed_action", None),
                        "target": output_data.get("proposed_target", None),
                        "justification": output_data.get("action_justification", None),
                        "reviewer_decision": output_data.get("reviewer_decision", None),
                        "simulated_blast_radius": output_data.get("simulated_blast_radius", None),
                        "historical_context_used": bool(output_data.get("historical_context")),
                        "learned_rule": output_data.get("learned_rule", None),
                        "execution_result": output_data.get("execution_result", None)
                    }
                    
                    logger.info(f"Streaming Node Completion: {node_name} | Status: {payload['internal_status_flag']}")
                    yield f"data: {json.dumps(payload)}\n\n"
                    
                    # Small artificial delay to allow UI animations to breathe
                    await asyncio.sleep(0.8)

            # 3. Successful Termination Event
            term_payload = {
                "node": "system", 
                "status": "terminated", 
                "message": "Simulation and adaptation cycle complete."
            }
            yield f"data: {json.dumps(term_payload)}\n\n"

        except Exception as e:
            logger.error(f"Graph execution failed: {str(e)}")
            error_payload = {
                "node": "system",
                "status": "error",
                "message": f"Critical Failure: {str(e)}"
            }
            yield f"data: {json.dumps(error_payload)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    # Optimized for local development. In production, remove reload=True.
    uvicorn.run("app.main:app", host="0.0.0.0", port=10000, reload=True)