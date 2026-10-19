import os
import re
import json
import logging
from typing import Type, TypeVar, Literal, Optional, Dict, Any

import requests
from pydantic import BaseModel, ValidationError
from langchain_openai import ChatOpenAI

logger = logging.getLogger("Zephyr-LLM")

T = TypeVar("T", bound=BaseModel)

# =====================================================================
# HYBRID INFRASTRUCTURE ENDPOINT & MODEL DEFAULTS (Master Spec Sec 1-3)
# =====================================================================

DEFAULT_RESPONDER_HOST = "http://127.0.0.1:11434"
DEFAULT_RESPONDER_MODEL = "zephyr-dpo-v3"  # Qwen2.5-7B-Instruct + QLoRA adapter

DEFAULT_SENSOR_HOST = "http://127.0.0.1:11435"
DEFAULT_SENSOR_MODEL = "qwen2.5-coder:7b-instruct"  # Zero-shot NIDS Sensor

DEFAULT_TIMEOUT_SECONDS = 45.0


def get_endpoint_config(role: Literal["responder", "sensor"] = "responder") -> Dict[str, Any]:
    """
    Resolves host, OpenAI-compatible base_url, and model name dynamically
    from environment variables with Master Spec defaults.
    """
    timeout = float(os.getenv("LLM_REQUEST_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS)))

    if role == "sensor":
        host = os.getenv("SENSOR_OLLAMA_HOST", DEFAULT_SENSOR_HOST).rstrip("/")
        base_url = os.getenv("SENSOR_BASE_URL", f"{host}/v1")
        model = os.getenv("SENSOR_MODEL", DEFAULT_SENSOR_MODEL)
    else:
        host = os.getenv("RESPONDER_OLLAMA_HOST", DEFAULT_RESPONDER_HOST).rstrip("/")
        base_url = os.getenv("RESPONDER_BASE_URL", f"{host}/v1")
        model = os.getenv("RESPONDER_MODEL", DEFAULT_RESPONDER_MODEL)

    return {
        "host": host,
        "base_url": base_url,
        "model": model,
        "timeout": timeout,
    }


def get_llm(
    temperature: float = 0.2,
    role: Literal["responder", "sensor"] = "responder",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> ChatOpenAI:
    """
    Initializes a LangChain ChatOpenAI client routed to the Ollama tunnel.
    Supports both the Responder (port 11434) and NIDS Sensor (port 11435).
    """
    cfg = get_endpoint_config(role=role)
    resolved_model = model or cfg["model"]
    resolved_base_url = base_url or cfg["base_url"]

    try:
        return ChatOpenAI(
            api_key="ollama",
            base_url=resolved_base_url,
            model=resolved_model,
            temperature=temperature,
            max_retries=2,
            request_timeout=cfg["timeout"],
        )
    except Exception as e:
        logger.error(f"Failed to initialize {role} LLM ({resolved_model} at {resolved_base_url}): {str(e)}")
        raise


def get_responder_llm(temperature: float = 0.1) -> ChatOpenAI:
    """Helper for Stage 2 JIT Mitigation & Reasoning LLM (Port 11434)."""
    return get_llm(temperature=temperature, role="responder")


def get_sensor_llm(temperature: float = 0.0) -> ChatOpenAI:
    """Helper for Stage 1 Semantic NIDS Sensor LLM (Port 11435)."""
    return get_llm(temperature=temperature, role="sensor")


# =====================================================================
# DETERMINISTIC JSON EXTRACTION & PYDANTIC-CONSTRAINED DECODING
# =====================================================================

def extract_json_payload(raw_text: str) -> str:
    """
    Strips optional <think>...</think> reasoning tags and Markdown code fences
    to isolate the raw JSON object string for Pydantic validation.
    """
    if not raw_text:
        raise ValueError("Empty LLM response text.")

    # Remove <think>...</think> blocks if emitted by reasoning models
    cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()

    # Strip ```json ... ``` fences if present
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
    if fence_match:
        return fence_match.group(1).strip()

    # Isolate outermost JSON braces {...}
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return cleaned[first_brace : last_brace + 1].strip()

    return cleaned


def invoke_structured_llm(
    system_prompt: str,
    user_prompt: str,
    response_model: Type[T],
    role: Literal["responder", "sensor"] = "responder",
    temperature: float = 0.1,
    max_retries: int = 2,
    model_override: Optional[str] = None,
    host_override: Optional[str] = None,
) -> T:
    """
    Queries the Ollama /api/chat endpoint using Pydantic-constrained JSON schema
    enforcement (`format=response_model.model_json_schema()`) and returns a
    validated instance of `response_model`.
    """
    cfg = get_endpoint_config(role=role)
    host = (host_override or cfg["host"]).rstrip("/")
    model = model_override or cfg["model"]
    timeout = cfg["timeout"]

    url = f"{host}/api/chat"
    json_schema = response_model.model_json_schema()

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "format": json_schema,
            "options": {
                "temperature": temperature,
            },
        }

        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()

            raw_content = data.get("message", {}).get("content", "")
            json_str = extract_json_payload(raw_content)
            return response_model.model_validate_json(json_str)

        except (ValidationError, ValueError, json.JSONDecodeError) as val_err:
            last_error = val_err
            logger.warning(
                f"[{role.upper()}] Schema validation failed on attempt {attempt}/{max_retries}: {val_err}"
            )
            # Append repair feedback for the next attempt
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Your previous output failed Pydantic schema validation with error:\n{val_err}\n"
                        "Return ONLY a valid JSON object strictly conforming to the schema."
                    ),
                }
            )
        except requests.RequestException as req_err:
            last_error = req_err
            logger.error(
                f"[{role.upper()}] HTTP connection failure to {url} on attempt {attempt}/{max_retries}: {req_err}"
            )
            break

    raise RuntimeError(
        f"Failed to obtain valid {response_model.__name__} from {role} LLM ({model} at {host}): {last_error}"
    ) from last_error


# =====================================================================
# BACKWARD-COMPATIBLE SINGLETONS (For existing LangGraph nodes)
# =====================================================================

local_llm = get_llm(temperature=0.2, role="responder")
creative_llm = get_llm(temperature=0.6, role="responder")