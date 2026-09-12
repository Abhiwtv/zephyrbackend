import os
import json
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from google import genai
from google.genai import errors
from dotenv import load_dotenv

# Load local .env if present. Silently ignored in Hugging Face Docker.
load_dotenv()

# Fail fast if the API key is missing
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY missing from environment.")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://your-soc-frontend.vercel.app")

app = FastAPI()

# Whitelist Frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the standard SDK
client = genai.Client(api_key=API_KEY)

class IncidentState(BaseModel):
    hypotheses: list[str]
    nids_alerts: list[dict]
    evidence: list[dict]

@app.get("/health")
def health_check():
    return {"status": "awake"}

async def generate_chat_stream(state: IncidentState):
    try:
        # Initial status update for the UI/3D nodes
        yield f"data: {json.dumps({'state': 'investigating', 'tool': 'get_server_logs'})}\n\n"
        
        # Example Gemini integration (Replace with actual agentic tool loop)
        # response = client.models.generate_content_stream(
        #     model="gemini-2.5-flash",
        #     contents=f"Determine next step based on state: {state.model_dump_json()}"
        # )
        # for chunk in response:
        #     yield f"data: {json.dumps({'state': 'reasoning', 'text': chunk.text})}\n\n"
        
        await asyncio.sleep(1) # Simulated delay for local testing
        yield f"data: {json.dumps({'state': 'complete', 'resolution': 'Plumbing active'})}\n\n"

    except errors.APIError as e:
        # Rate limit / Resource Exhaustion defense (15 RPM free tier)
        if e.code == 429:
             yield f"data: {json.dumps({'state': 'paused', 'error': 'Rate limit hit, applying backoff...'})}\n\n"
             await asyncio.sleep(4) # Brief pause before client retry
        else:
             yield f"data: {json.dumps({'state': 'error', 'error': str(e)})}\n\n"

@app.post("/api/chat")
async def chat_endpoint(state: IncidentState):
    return StreamingResponse(generate_chat_stream(state), media_type="text/event-stream")