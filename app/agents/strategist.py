import logging
from typing import Dict, Any
from langchain_core.prompts import ChatPromptTemplate
from app.core.state import IncidentState
from app.core.llm import creative_llm
from app.tools.mock_env import soc_tools

logger = logging.getLogger("Zephyr-Strategist")
logger.setLevel(logging.INFO)

def strategist_node(state: IncidentState) -> Dict[str, Any]:
    """
    Tool-binding node. Interprets the missing evidence requirements and invokes 
    the environment's sandbox tools (e.g., check_server_logs, check_vulnerability).
    """
    logger.info(f"[{state.incident_id}] === EVIDENCE PLANNING PHASE INITIATED ===")
    
    # Bind the available tools to the LLM so it knows what it can execute
    llm_with_tools = creative_llm.bind_tools(soc_tools)
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are an Evidence Strategist. 
        Read the investigator's requirements and call the exact tools needed to satisfy them.
        If no tools match the requirements, return a plain text response stating you cannot proceed."""),
        ("user", "Target IP: {target}\nMissing Evidence Context:\n{messages}")
    ])
    
    # Extract only the textual content from previous messages for clean prompting
    context = "\n".join([msg.content for msg in state.messages if isinstance(msg.content, str)])
    
    logger.debug(f"[{state.incident_id}] Binding tools and invoking LLM...")
    
    try:
        chain = prompt | llm_with_tools
        response = chain.invoke({
            "target": state.target_ip, 
            "messages": context
        })
        
        if response.tool_calls:
            logger.info(f"[{state.incident_id}] Strategist generated {len(response.tool_calls)} tool call(s): {[tc['name'] for tc in response.tool_calls]}")
        else:
            logger.warning(f"[{state.incident_id}] Strategist failed to map requirements to tools. Fallback response generated.")
            
        return {
            "status": "EVIDENCE_PLANNING",
            # We append the AIMessage containing the tool_calls; the graph will automatically route this to the ToolNode
            "messages": [response]
        }
        
    except Exception as e:
        logger.error(f"[{state.incident_id}] Strategist tool-binding failure: {str(e)}")
        raise e