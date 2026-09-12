import os
import json
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from google import genai
from google.genai import types, errors
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY missing from environment.")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:3000", "https://your-soc-frontend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        yield f"data: {json.dumps({'state': 'investigating'})}\n\n"
        
        prompt = f"""
        You are an expert SOC Analyst Agent. Analyze the current incident state and provide a brief, 
        2-sentence hypothesis of what is happening.
        
        Current State:
        {state.model_dump_json()}
        """
        
        # Thinking budget explicitly set to 0 to disable reasoning and drop latency
        # Thinking level explicitly set to MINIMAL to disable reasoning and drop latency
        response = await client.aio.models.generate_content_stream(
            model="gemini-3.6-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="MINIMAL")
            )
        )
        
        async for chunk in response:
            if chunk.text:
                yield f"data: {json.dumps({'state': 'reasoning', 'text': chunk.text})}\n\n"
                
        yield f"data: {json.dumps({'state': 'complete', 'resolution': 'Analysis complete.'})}\n\n"

    except errors.APIError as e:
        if e.code == 429:
             yield f"data: {json.dumps({'state': 'paused', 'error': 'Rate limit hit, applying backoff...'})}\n\n"
        else:
             yield f"data: {json.dumps({'state': 'error', 'error': str(e)})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'state': 'error', 'error': 'Internal Server Error: ' + str(e)})}\n\n"

@app.post("/api/chat")
async def chat_endpoint(state: IncidentState):
    return StreamingResponse(generate_chat_stream(state), media_type="text/event-stream")