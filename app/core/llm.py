from langchain_ollama import ChatOllama

local_llm = ChatOllama(
    model="llama3.1",
    temperature=0
)