# Security Incident Correlation & Threat Intelligence Platform

A practical Level 3 DBMS mini project demonstrating relational modeling in PostgreSQL, flexible raw-event storage in MongoDB, and correlation of security events into explainable incidents.

## What it does

- Ingests security events through a web form or REST API.
- Extracts IP addresses, domains, and file hashes from event summaries and payloads.
- Stores normalized records and relationships in PostgreSQL and original event documents in MongoDB.
- Correlates events that share indicators within a configurable time window, records the match evidence, and creates or updates incidents.
- Provides an analyst dashboard for reviewing incidents, their evidence, and event timelines.
- Includes source management, user roles, and an audit trail for incident status changes.
- Gives administrators user and event-source management tools.

## Run locally

1. Install Docker Desktop and start it.
2. Copy `.env.example` to `.env`. Set unique passwords of at least 12 characters for PostgreSQL, MongoDB, the admin account, and the analyst account. Set `APP_SECRET` to a random value of at least 32 characters. These values stay in your local `.env` file and must not be committed.
3. Start the stack with `docker compose up --build`.
4. Open [http://localhost:8000](http://localhost:8000).

The compose stack starts PostgreSQL, MongoDB, and the FastAPI application. PostgreSQL initializes its tables from `database/schema.sql` on the first run. MongoDB initializes the `raw_events` collection and indexes when the API starts.

The bootstrap accounts are `admin@local.test` and `analyst@local.test`; their passwords are the local values you set in `BOOTSTRAP_ADMIN_PASSWORD` and `BOOTSTRAP_ANALYST_PASSWORD`. API docs are available at `/docs`.

To stop the services, run `docker compose down`. To also remove the local database volumes and their data, run `docker compose down -v`.

## Correlation behavior

Each event is normalized and its indicators are upserted into PostgreSQL. The service finds prior events sharing at least one indicator, within the configured time window (default 30 minutes). It creates a new incident for a new cluster or attaches the event to the matching open incident. The `incident_events.match_reason` field preserves the indicator and time-window evidence used for each link.

## Database design

PostgreSQL stores users, sources, events, indicators, event-indicator relationships, incidents, incident-event evidence, and audit logs. Foreign keys, uniqueness rules, check constraints, indexes, and a PostgreSQL transaction protect relational integrity during ingestion. If the PostgreSQL write fails after the raw MongoDB document is saved, the app removes that document as compensation. MongoDB stores each original, variable-shaped event payload, referenced from PostgreSQL by `raw_doc_id`.

The ER diagram source is [`database/erd.mmd`](database/erd.mmd). It can be pasted into Mermaid Live Editor or rendered by GitHub Markdown.

## Walkthrough for a project demonstration

1. Sign in as the administrator and show the user and source management screens.
2. Open **Event stream → Ingest event**. Select Firewall, set a recent timestamp and high severity, then enter a summary containing `185.220.101.45`.
3. Ingest a second event from Endpoint Monitor with the same IP and a timestamp a few minutes later.
4. Open **Incidents**. Select the generated incident and show the two event records, shared-IP evidence, and correlation window.
5. Change the incident to **Investigating**, then **Resolved**. Show both changes in **Audit log**.
6. Open `/docs` and show the API endpoints. Use `GET /api/events/{event_id}/raw` to demonstrate that the original payload is stored in MongoDB.
7. Show the normalized PostgreSQL tables and indexes with the database commands below.

```bash
docker compose exec postgres psql -U secops_dev -d security_platform -c '\\dt'
docker compose exec postgres psql -U secops_dev -d security_platform -c 'SELECT e.summary, i.type, i.normalized_value FROM events e JOIN event_indicators ei USING(event_id) JOIN indicators i USING(indicator_id);'
docker compose exec mongo mongosh -u secops_dev -p --authenticationDatabase admin threat_intel --eval 'db.raw_events.findOne()'
```

## Project structure

```text
app/                 FastAPI routes and database services
database/schema.sql  PostgreSQL schema
static/              Browser dashboard
docker-compose.yml   Local development stack
```

## Example API calls

```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/events
curl http://localhost:8000/api/incidents
```

Submit an event with `POST /api/events` using JSON fields `source_id`, `occurred_at` (ISO 8601), `severity` (`low`, `medium`, `high`, or `critical`), `summary`, and optional `payload`.

## Assignment demonstration checklist

- Show the ER model and explain the one-to-many and many-to-many relationships.
- Demonstrate primary keys, foreign keys, constraints, and indexes in PostgreSQL.
- Explain why normalized incident data uses SQL and variable raw payloads use MongoDB.
- Ingest two events containing the same indicator within 30 minutes and show the generated incident and recorded match reason.
- Change incident status as an analyst and show the audit log.
- Show admin-only source/user administration and the API documentation.

## Security note

This is an educational local prototype. Use strong secrets, TLS, managed secret storage, and a production-grade deployment review before exposing it to a network.

