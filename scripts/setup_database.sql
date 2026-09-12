-- Enable the pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- 1. Textbook Playbooks (Phase 1 RAG)
DROP TABLE IF EXISTS soc_playbooks CASCADE;
CREATE TABLE soc_playbooks (
    id bigserial PRIMARY KEY,
    category text,
    signature text,
    content text,  -- The Textbook SOP
    embedding vector(384) -- all-MiniLM-L6-v2 uses 384 dimensions
);

-- Function to query Phase 1 Playbooks
CREATE FUNCTION match_soc_playbooks (query_embedding vector(384), match_count int DEFAULT 1)
RETURNS TABLE (id bigint, category text, content text, similarity float)
LANGUAGE sql STABLE AS $$
  SELECT id, category, content, 1 - (embedding <=> query_embedding) AS similarity
  FROM soc_playbooks 
  ORDER BY embedding <=> query_embedding 
  LIMIT match_count;
$$;

-- 2. Server Logs (For the Investigator/Strategist tools)
DROP TABLE IF EXISTS server_logs CASCADE;
CREATE TABLE server_logs (
    id bigserial PRIMARY KEY,
    incident_id text,
    content text,
    metadata jsonb,
    embedding vector(384)
);

CREATE FUNCTION match_server_logs (query_embedding vector(384), match_count int DEFAULT 3)
RETURNS TABLE (id bigint, incident_id text, content text, metadata jsonb, similarity float)
LANGUAGE sql STABLE AS $$
  SELECT id, incident_id, content, metadata, 1 - (embedding <=> query_embedding) AS similarity
  FROM server_logs 
  ORDER BY embedding <=> query_embedding 
  LIMIT match_count;
$$;

-- 3. Episodic Memory / Postmortems (Phase 2 RAG - Empty at start)
DROP TABLE IF EXISTS incident_postmortems CASCADE;
CREATE TABLE incident_postmortems (
    id bigserial PRIMARY KEY,
    incident_id text,
    content text,
    metadata jsonb,
    embedding vector(384)
);

CREATE FUNCTION match_incident_postmortems (query_embedding vector(384), match_count int DEFAULT 2)
RETURNS TABLE (id bigint, incident_id text, content text, metadata jsonb, similarity float)
LANGUAGE sql STABLE AS $$
  SELECT id, incident_id, content, metadata, 1 - (embedding <=> query_embedding) AS similarity
  FROM incident_postmortems 
  -- Only return high confidence matches to avoid hallucinating false overrides
  WHERE 1 - (embedding <=> query_embedding) > 0.5 
  ORDER BY embedding <=> query_embedding 
  LIMIT match_count;
$$;

-- 4. The Relational Audit Trail (For the Hackathon UI Dashboard)
DROP TABLE IF EXISTS learning_ledger CASCADE;
CREATE TABLE learning_ledger (
    id bigserial PRIMARY KEY,
    incident_id text NOT NULL,
    original_action text,
    failure_reason text,
    new_rule_learned text,
    created_at timestamp DEFAULT now()
);