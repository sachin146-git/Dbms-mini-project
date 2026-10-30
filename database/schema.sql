CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE user_role AS ENUM ('admin', 'analyst');
CREATE TYPE event_severity AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE incident_status AS ENUM ('open', 'investigating', 'resolved', 'false_positive');
CREATE TYPE indicator_type AS ENUM ('ip', 'domain', 'md5', 'sha1', 'sha256');

CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role user_role NOT NULL DEFAULT 'analyst',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sources (
  source_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  source_type TEXT NOT NULL,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE indicators (
  indicator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type indicator_type NOT NULL,
  normalized_value TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (type, normalized_value)
);

CREATE TABLE events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
  occurred_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  severity event_severity NOT NULL,
  summary TEXT NOT NULL,
  raw_doc_id TEXT NOT NULL UNIQUE
);

CREATE TABLE event_indicators (
  event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  indicator_id UUID NOT NULL REFERENCES indicators(indicator_id) ON DELETE RESTRICT,
  PRIMARY KEY (event_id, indicator_id)
);

CREATE TABLE incidents (
  incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  severity event_severity NOT NULL,
  status incident_status NOT NULL DEFAULT 'open',
  owner_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE incident_events (
  incident_id UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
  event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  match_reason TEXT NOT NULL,
  linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE audit_logs (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX events_occurred_at_idx ON events (occurred_at DESC);
CREATE INDEX events_severity_idx ON events (severity);
CREATE INDEX event_indicators_indicator_idx ON event_indicators (indicator_id, event_id);
CREATE INDEX incidents_status_updated_idx ON incidents (status, updated_at DESC);
CREATE INDEX incident_events_event_idx ON incident_events (event_id);
CREATE INDEX audit_logs_created_idx ON audit_logs (created_at DESC);

INSERT INTO sources (name, source_type, description) VALUES
  ('Firewall', 'network', 'Perimeter firewall alerts'),
  ('Endpoint Monitor', 'endpoint', 'Endpoint detection alerts'),
  ('Email Gateway', 'email', 'Suspicious email reports')
ON CONFLICT (name) DO NOTHING;

