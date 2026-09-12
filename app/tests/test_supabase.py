import os
import pytest
from dotenv import load_dotenv
from supabase.client import create_client, Client
from langchain_huggingface import HuggingFaceEmbeddings

load_dotenv()

@pytest.fixture(scope="module")
def db_client() -> Client:
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_KEY")
    assert url and key, "Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in environment"
    return create_client(url, key)

@pytest.fixture(scope="module")
def embedding_model() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

def test_supabase_connection(db_client: Client):
    """Verify Supabase API connectivity and table existence."""
    tables = ["soc_playbooks", "server_logs", "incident_postmortems", "learning_ledger"]
    for table in tables:
        response = db_client.table(table).select("id").limit(1).execute()
        assert response.data is not None, f"Failed to query table: {table}"

def test_playbook_vector_match_rpc(db_client: Client, embedding_model: HuggingFaceEmbeddings):
    """Verify pgvector similarity search RPC function executes properly."""
    query = "ET EXPLOIT Apache log4j RCE Attempt"
    vector = embedding_model.embed_query(query)
    
    # RPC parameters matching scripts/setup_database.sql
    response = db_client.rpc(
        "match_soc_playbooks",
        {"query_embedding": vector, "match_count": 1}
    ).execute()
    
    assert response.data is not None, "RPC match_soc_playbooks returned None"
    assert len(response.data) > 0, "No playbooks matched; check if seed_database.py was run"
    assert "content" in response.data[0]
    assert "similarity" in response.data[0]

def test_learning_ledger_insert(db_client: Client):
    """Verify write access to the relational ledger table."""
    test_entry = {
        "incident_id": "INC-TEST-001",
        "original_action": "BLOCK_SOURCE on 1.1.1.1",
        "failure_reason": "SIMULATION_TEST_RUN",
        "new_rule_learned": "Never block critical public resolvers."
    }
    insert_res = db_client.table("learning_ledger").insert(test_entry).execute()
    assert len(insert_res.data) == 1
    
    # Clean up test row
    db_client.table("learning_ledger").delete().eq("incident_id", "INC-TEST-001").execute()

if __name__ == "__main__":
    import sys
    sys.exit(pytest.main(["-v", "-s", __file__]))