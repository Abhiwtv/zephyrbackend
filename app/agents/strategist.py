from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
from app.core.state import IncidentState
from app.core.llm import local_llm
from app.tools.mock_env import soc_tools

# Bind tools to the local LLM so it knows they exist
llm_with_tools = local_llm.bind_tools(soc_tools)

def strategist_node(state: IncidentState) -> dict:
    """
    STATE 3: EVIDENCE_PLANNING
    The LLM reviews missing evidence and decides which tool to call.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are an Evidence Strategist. Look at the missing evidence and call the appropriate tool to retrieve it. Only call one tool at a time."),
        ("user", "Target IP: {target}\nMissing Evidence: {missing}")
    ])
    
    chain = prompt | llm_with_tools
    
    response = chain.invoke({
        "target": state.target_ip,
        "missing": ", ".join(state.missing_evidence)
    })
    
    return {
        "status": "EVIDENCE_PLANNING",
        "messages": [response]
    }