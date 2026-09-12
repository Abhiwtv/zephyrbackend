import os
import logging
from typing import Optional, List, Dict, Any
from supabase.client import Client, create_client
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import SupabaseVectorStore
from dotenv import load_dotenv

load_dotenv()

# Configure highly verbose logging for the memory fabric
logger = logging.getLogger("Zephyr-RAG")
logger.setLevel(logging.INFO)

# Initialize the embedding model natively (CPU-bound for fast, local execution)
try:
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    logger.info("Successfully loaded HuggingFaceEmbeddings (all-MiniLM-L6-v2).")
except Exception as e:
    logger.error(f"Failed to load embedding model: {e}")
    raise e

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")

if not supabase_url or not supabase_key:
    raise ValueError("Missing Supabase credentials (SUPABASE_URL, SUPABASE_SERVICE_KEY) in .env")

try:
    supabase_client: Client = create_client(supabase_url, supabase_key)
    logger.info("Supabase client initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {e}")
    raise e


def get_playbook_retriever(k: int = 1):
    """
    Phase 1 Retrieval: Retrieves standard baseline SOC procedures.
    """
    logger.info(f"Initializing Playbook Retriever (k={k})")
    vector_store = SupabaseVectorStore(
        embedding=embeddings,
        client=supabase_client,
        table_name="soc_playbooks",
        query_name="match_soc_playbooks"
    )
    return vector_store.as_retriever(search_kwargs={"k": k})


def get_postmortem_retriever(k: int = 2):
    """
    Phase 2 Retrieval: Retrieves historically adapted episodic memory.
    """
    logger.info(f"Initializing Postmortem Retriever (k={k})")
    vector_store = SupabaseVectorStore(
        embedding=embeddings,
        client=supabase_client,
        table_name="incident_postmortems",
        query_name="match_incident_postmortems"
    )
    return vector_store.as_retriever(search_kwargs={"k": k})


def save_learned_policy(incident_id: str, rule: str, target_class: str) -> None:
    """
    Embeds the mutated policy into episodic memory. 
    Implements a strict deduplication check against context bloat.
    """
    logger.info(f"RAG: Attempting to save new learned policy for incident {incident_id}")
    
    vector_store = SupabaseVectorStore(
        embedding=embeddings, 
        client=supabase_client, 
        table_name="incident_postmortems", 
        query_name="match_incident_postmortems"
    )
    
    try:
        # Check for semantic duplicates. 
        # The Supabase pgvector function returns 1 - (embedding <=> query) as similarity.
        docs_and_scores = vector_store.similarity_search_with_score(rule, k=1)
        
        if docs_and_scores:
            doc, similarity = docs_and_scores[0]
            if similarity > 0.85:
                logger.warning(f"RAG Deduplication: Rule skipped. Semantic duplicate found (Similarity: {similarity:.3f})")
                logger.debug(f"Matched existing rule: {doc.page_content}")
                return

        metadata = {"incident_id": incident_id, "target_class": target_class}
        vector_store.add_texts(texts=[rule], metadatas=[metadata])
        logger.info(f"RAG: Successfully embedded new episodic memory (Class: {target_class})")
        
    except Exception as e:
        logger.error(f"RAG: Failed to save learned policy: {str(e)}")


def write_learning_ledger(incident_id: str, failed_action: str, blast_radius: str, rule: str) -> None:
    """
    Relational insert to power the hackathon dashboard. 
    Provides mathematically provable evidence of adaptation over time.
    """
    logger.info(f"RAG: Writing to relational learning ledger for {incident_id}")
    data = {
        "incident_id": incident_id,
        "original_action": failed_action,
        "failure_reason": blast_radius,
        "new_rule_learned": rule
    }
    
    try:
        response = supabase_client.table("learning_ledger").insert(data).execute()
        logger.info(f"RAG: Ledger updated successfully. Rows inserted: {len(response.data)}")
    except Exception as e:
        logger.error(f"RAG: Failed to write to learning ledger: {str(e)}")