from fastapi import FastAPI
from pydantic import BaseModel
from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

app = FastAPI(title="Autonomous SOC API")

# This perfectly matches the incoming NIDS payload
class NIDSAlert(BaseModel):
    alert_id: str
    signature: str
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: str

@app.post("/alert")
async def process_nids_alert(payload: NIDSAlert):
    # Initialize the state with the raw NIDS context
    initial_state = IncidentState(
        incident_id=payload.alert_id,
        alert_signature=payload.signature,
        source_ip=payload.src_ip,
        target_ip=payload.dst_ip
    )
    
    # Fire the LangGraph orchestrator
    result = soc_graph.invoke(initial_state.model_dump())
    return result