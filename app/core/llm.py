import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# Force Python to read the local .env file immediately
load_dotenv()

local_llm = ChatGroq(
    api_key=os.getenv("GROQ_API_KEY"),
    model_name="openai/gpt-oss-20b",
    temperature=0.2
)