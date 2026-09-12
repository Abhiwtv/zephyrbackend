import logging
from langchain_openai import ChatOpenAI
from langchain_core.exceptions import OutputParserException

logger = logging.getLogger("Zephyr-LLM")

def get_llm(temperature: float = 0.2) -> ChatOpenAI:
    """
    Initializes the local LLM.
    Uses the ChatOpenAI class routed to the local Ollama v1 API endpoint.
    This provides superior native tool-calling (function binding) support for Llama 3.1 8B.
    """
    try:
        llm = ChatOpenAI(
            api_key="ollama", # Placeholder required by the OpenAI client
            base_url="http://127.0.0.1:11434/v1",
            model="llama3.1",
            temperature=temperature,
            max_retries=3,          # Critical for agentic loops to survive temporary hallucination crashes
            request_timeout=120.0   # Generous timeout for local inference on an RTX 4050
        )
        return llm
    except Exception as e:
        logger.error(f"Failed to initialize local LLM: {str(e)}")
        raise e

# Instantiate a default singleton instance for general nodes
local_llm = get_llm(temperature=0.2)

# Instantiate a high-creativity instance specifically for the Strategist and RART nodes
# to allow better semantic abstraction and out-of-the-box thinking.
creative_llm = get_llm(temperature=0.6)