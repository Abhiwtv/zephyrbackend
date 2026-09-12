from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

# Point directly to your local Ollama port
llm = ChatOpenAI(
    api_key="ollama",
    base_url="http://localhost:11434/v1",
    model="llama3.1",
    temperature=0.2
)

response = llm.invoke([HumanMessage(content="Explain what a SIEM is in exactly one sentence.")])
print(response.content)