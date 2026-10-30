from __future__ import annotations

import ipaddress
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from starlette.staticfiles import StaticFiles

PG_DSN = "host={host} port={port} dbname={db} user={user} password={password}".format(
    host=os.getenv("POSTGRES_HOST", "localhost"), port=os.getenv("POSTGRES_PORT", "5432"),
    db=os.getenv("POSTGRES_DB", "security_platform"), user=os.getenv("POSTGRES_USER", "secops_dev"),
    password=os.getenv("POSTGRES_PASSWORD", ""),
)
MONGO_URI = "mongodb://{user}:{password}@{host}:{port}/?authSource=admin".format(
    user=os.getenv("MONGO_INITDB_ROOT_USERNAME", "secops_dev"),
    password=os.getenv("MONGO_INITDB_ROOT_PASSWORD", ""),
    host=os.getenv("MONGO_HOST", "localhost"), port=os.getenv("MONGO_PORT", "27017"),
)
MONGO_DB = os.getenv("MONGO_DATABASE", "threat_intel")
APP_SECRET = os.getenv("APP_SECRET", "")
WINDOW_MINUTES = max(1, int(os.getenv("CORRELATION_WINDOW_MINUTES", "30")))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")
pool: ConnectionPool | None = None
mongo: MongoClient | None = None


class EventIn(BaseModel):
    source_id: UUID
    occurred_at: datetime
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    summary: str = Field(min_length=3, max_length=2000)
    payload: dict[str, Any] = Field(default_factory=dict)


class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    source_type: str = Field(min_length=2, max_length=80)
    description: str | None = None


class UserIn(BaseModel):
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern="^(admin|analyst)$")


class StatusIn(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|false_positive)$")


def db_conn():
    if pool is None:
        raise HTTPException(503, "Database is starting")
    return pool.connection()


def extract_indicators(text: str) -> list[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,39}\b", text):
        try:
            found.add(("ip", str(ipaddress.ip_address(candidate))))
        except ValueError:
            continue
    for domain in re.findall(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text):
        if not domain.lower().endswith((".local", ".test", ".example")):
            found.add(("domain", domain.lower().rstrip(".")))
    for kind, pattern in (("sha256", r"\b[a-fA-F0-9]{64}\b"), ("sha1", r"\b[a-fA-F0-9]{40}\b"), ("md5", r"\b[a-fA-F0-9]{32}\b")):
        for value in re.findall(pattern, text):
            found.add((kind, value.lower()))
    return sorted(found)


def current_user(token: str = Depends(oauth2)) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("missing subject")
        with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT user_id, email, role FROM users WHERE user_id=%s", (user_id,))
            user = cur.fetchone()
        if not user:
            raise ValueError("unknown user")
        return user
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token", headers={"WWW-Authenticate": "Bearer"})


def require_admin(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator role required")
    return user


def create_token(user: dict[str, Any]) -> str:
    return jwt.encode({"sub": str(user["user_id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, APP_SECRET, algorithm="HS256")


def seed_users() -> None:
    with db_conn() as conn, conn.cursor() as cur:
        for email, role, envvar in (("admin@local.test", "admin", "BOOTSTRAP_ADMIN_PASSWORD"), ("analyst@local.test", "analyst", "BOOTSTRAP_ANALYST_PASSWORD")):
            password = os.getenv(envvar, "")
            if len(password) < 12:
                raise RuntimeError(f"Set {envvar} to a unique password with at least 12 characters")
            cur.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING", (email, pwd_context.hash(password), role))


@asynccontextmanager
async def lifespan(_: FastAPI):
    global pool, mongo
    if len(APP_SECRET) < 32:
        raise RuntimeError("Set APP_SECRET to a random value with at least 32 characters")
    last_error: Exception | None = None
    for _attempt in range(30):
        try:
            pool = ConnectionPool(PG_DSN, min_size=1, max_size=10, kwargs={"row_factory": dict_row}, open=True)
            pool.wait(timeout=5)
            mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            mongo.admin.command("ping")
            mongo[MONGO_DB].raw_events.create_index("event_id", unique=True)
            mongo[MONGO_DB].raw_events.create_index([("source_id", 1), ("received_at", -1)])
            seed_users()
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            if pool:
                pool.close()
                pool = None
            if mongo:
                mongo.close()
                mongo = None
            time.sleep(2)
    if last_error:
        raise RuntimeError(f"Could not connect to PostgreSQL and MongoDB: {last_error}")
    yield
    if pool:
        pool.close()
    if mongo:
        mongo.close()


app = FastAPI(title="SIC Threat Intelligence Platform", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    try:
        with db_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        mongo.admin.command("ping")
        return {"status": "ok", "postgres": "connected", "mongodb": "connected"}
    except Exception as exc:
        raise HTTPException(503, f"Database health check failed: {exc}")


@app.post("/api/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT user_id,email,role,password_hash FROM users WHERE email=%s", (form.username.lower(),))
        user = cur.fetchone()
    if not user or not pwd_context.verify(form.password, user["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_token(user), "token_type": "bearer", "email": user["email"], "role": user["role"]}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(current_user)):
    return {"user_id": str(user["user_id"]), "email": user["email"], "role": user["role"]}


@app.get("/api/dashboard")
def dashboard(_: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT (SELECT count(*) FROM events) AS events, (SELECT count(*) FROM incidents WHERE status IN ('open','investigating')) AS active_incidents, (SELECT count(*) FROM indicators) AS indicators, (SELECT count(*) FROM sources WHERE enabled) AS sources")
        counts = cur.fetchone()
        cur.execute("SELECT severity,count(*) AS count FROM incidents WHERE status IN ('open','investigating') GROUP BY severity")
        counts["severity_breakdown"] = cur.fetchall()
        cur.execute("SELECT indicator_type,normalized_value,count(*) AS event_count FROM (SELECT i.type AS indicator_type,i.normalized_value,ei.event_id FROM indicators i JOIN event_indicators ei USING(indicator_id)) x GROUP BY indicator_type,normalized_value ORDER BY event_count DESC LIMIT 6")
        counts["top_indicators"] = cur.fetchall()
    return counts


@app.get("/api/sources")
def list_sources(_: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT source_id,name,source_type,description,enabled,created_at FROM sources ORDER BY name")
        return cur.fetchall()


@app.get("/api/users")
def list_users(_: dict[str, Any] = Depends(require_admin)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT user_id,email,role,created_at FROM users ORDER BY created_at")
        return cur.fetchall()


@app.post("/api/users", status_code=201)
def add_user(body: UserIn, admin: dict[str, Any] = Depends(require_admin)):
    email = body.email.lower()
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) RETURNING user_id,email,role,created_at", (email, pwd_context.hash(body.password), body.role))
            user = cur.fetchone()
            cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'user.created','user',%s,%s)", (admin["user_id"], user["user_id"], psycopg.types.json.Jsonb({"email": email, "role": body.role})))
            return user
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "A user with that email already exists")


@app.post("/api/sources", status_code=201)
def add_source(body: SourceIn, admin: dict[str, Any] = Depends(require_admin)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute("INSERT INTO sources(name,source_type,description) VALUES (%s,%s,%s) RETURNING *", (body.name, body.source_type, body.description))
            row = cur.fetchone()
            cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'source.created','source',%s,%s)", (admin["user_id"], row["source_id"], psycopg.types.json.Jsonb({"name": body.name})))
            return row
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "A source with that name already exists")


def ingest_event(body: EventIn, actor: dict[str, Any] | None = None) -> dict[str, Any]:
    if mongo is None:
        raise HTTPException(503, "MongoDB is unavailable")
    timestamp = body.occurred_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    payload_text = body.summary + " " + str(body.payload)
    indicators = extract_indicators(payload_text)
    raw_document = {"source_id": str(body.source_id), "occurred_at": timestamp, "received_at": now, "severity": body.severity, "summary": body.summary, "payload": body.payload}
    raw_id = mongo[MONGO_DB].raw_events.insert_one(raw_document).inserted_id
    raw_doc_id = str(raw_id)
    try:
        with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT source_id FROM sources WHERE source_id=%s AND enabled=true", (body.source_id,))
            if not cur.fetchone():
                raise HTTPException(404, "Enabled event source not found")
            cur.execute("INSERT INTO events(source_id,occurred_at,severity,summary,raw_doc_id) VALUES (%s,%s,%s,%s,%s) RETURNING event_id,source_id,occurred_at,received_at,severity,summary,raw_doc_id", (body.source_id, timestamp, body.severity, body.summary, raw_doc_id))
            event = cur.fetchone()
            indicator_rows = []
            for kind, value in indicators:
                cur.execute("INSERT INTO indicators(type,normalized_value,first_seen,last_seen) VALUES (%s,%s,%s,%s) ON CONFLICT(type,normalized_value) DO UPDATE SET last_seen=GREATEST(indicators.last_seen,EXCLUDED.last_seen) RETURNING indicator_id,type,normalized_value", (kind, value, timestamp, timestamp))
                indicator = cur.fetchone()
                cur.execute("INSERT INTO event_indicators(event_id,indicator_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (event["event_id"], indicator["indicator_id"]))
                indicator_rows.append(indicator)
            cur.execute("""SELECT DISTINCT i.indicator_id,i.type,i.normalized_value,e.event_id,e.occurred_at,e.severity,e.summary,ie.incident_id
                FROM event_indicators current_ei JOIN indicators i USING(indicator_id)
                JOIN event_indicators old_ei ON old_ei.indicator_id=i.indicator_id
                JOIN events e ON e.event_id=old_ei.event_id
                LEFT JOIN incident_events ie ON ie.event_id=e.event_id
                LEFT JOIN incidents related ON related.incident_id=ie.incident_id
                WHERE current_ei.event_id=%s AND e.event_id<>%s AND e.occurred_at BETWEEN %s AND %s
                AND (ie.incident_id IS NULL OR related.status IN ('open','investigating'))
                ORDER BY e.occurred_at DESC LIMIT 50""", (event["event_id"], event["event_id"], timestamp-timedelta(minutes=WINDOW_MINUTES), timestamp+timedelta(minutes=WINDOW_MINUTES)))
            raw_matches = cur.fetchall()
            matches_by_event: dict[UUID, dict[str, Any]] = {}
            for matched in raw_matches:
                prior_event = matches_by_event.setdefault(matched["event_id"], {**matched, "shared_indicators": set()})
                prior_event["shared_indicators"].add((matched["type"], matched["normalized_value"]))
            matches = list(matches_by_event.values())
            incident_id = None
            match_reason = None
            if matches:
                existing = next((m["incident_id"] for m in matches if m["incident_id"]), None)
                if existing:
                    incident_id = existing
                else:
                    prior = matches[0]
                    cur.execute("INSERT INTO incidents(title,severity,owner_user_id) VALUES (%s,%s,%s) RETURNING incident_id", (f"Correlated activity: {body.summary[:100]}", max((body.severity, prior["severity"]), key=("low", "medium", "high", "critical").index), actor["user_id"] if actor else None))
                    incident_id = cur.fetchone()["incident_id"]
                for matched in matches:
                    indicators_text = ", ".join(f"{kind} {value}" for kind, value in sorted(matched["shared_indicators"]))
                    why = f"Shared indicator(s): {indicators_text} within {WINDOW_MINUTES} minutes"
                    cur.execute("INSERT INTO incident_events(incident_id,event_id,match_reason) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (incident_id, matched["event_id"], why))
                shared = matches[0]
                match_reason = f"Shares {shared['type']} {shared['normalized_value']} with {len(matches)} prior event(s) inside the {WINDOW_MINUTES}-minute window"
                cur.execute("INSERT INTO incident_events(incident_id,event_id,match_reason) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (incident_id, event["event_id"], match_reason))
                cur.execute("UPDATE incidents SET updated_at=now(), severity=GREATEST(severity, %s::event_severity) WHERE incident_id=%s", (body.severity, incident_id))
            if actor:
                cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'event.ingested','event',%s,%s)", (actor["user_id"], event["event_id"], psycopg.types.json.Jsonb({"indicator_count": len(indicators), "matched_count": len(matches)})))
            event["indicators"] = indicator_rows
            event["incident_id"] = incident_id
            event["match_reason"] = match_reason
            return event
    except Exception:
        mongo[MONGO_DB].raw_events.delete_one({"_id": raw_id})
        raise


@app.post("/api/events", status_code=201)
def create_event(body: EventIn, user: dict[str, Any] = Depends(current_user)):
    try:
        return ingest_event(body, user)
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(404, "Event source not found")


@app.get("/api/events")
def list_events(_: dict[str, Any] = Depends(current_user), limit: int = Query(50, ge=1, le=200)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""SELECT e.event_id,e.occurred_at,e.received_at,e.severity,e.summary,s.name AS source_name,
            COALESCE(json_agg(json_build_object('type',i.type,'value',i.normalized_value)) FILTER (WHERE i.indicator_id IS NOT NULL),'[]') AS indicators
            FROM events e JOIN sources s USING(source_id) LEFT JOIN event_indicators ei USING(event_id) LEFT JOIN indicators i USING(indicator_id)
            GROUP BY e.event_id,s.name ORDER BY e.occurred_at DESC LIMIT %s""", (limit,))
        return cur.fetchall()


@app.get("/api/events/{event_id}/raw")
def get_raw_event(event_id: UUID, _: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT raw_doc_id FROM events WHERE event_id=%s", (event_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Event not found")
    try:
        from bson import ObjectId
        document = mongo[MONGO_DB].raw_events.find_one({"_id": ObjectId(row["raw_doc_id"])})
    except Exception:
        document = None
    if not document:
        raise HTTPException(404, "Raw event payload not found in MongoDB")
    document["_id"] = str(document["_id"])
    return document


@app.get("/api/incidents")
def lisfrom __future__ import annotations

import ipaddress
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from starlette.staticfiles import StaticFiles

PG_DSN = "host={host} port={port} dbname={db} user={user} password={password}".format(
    host=os.getenv("POSTGRES_HOST", "localhost"), port=os.getenv("POSTGRES_PORT", "5432"),
    db=os.getenv("POSTGRES_DB", "security_platform"), user=os.getenv("POSTGRES_USER", "secops_dev"),
    password=os.getenv("POSTGRES_PASSWORD", ""),
)
MONGO_URI = "mongodb://{user}:{password}@{host}:{port}/?authSource=admin".format(
    user=os.getenv("MONGO_INITDB_ROOT_USERNAME", "secops_dev"),
    password=os.getenv("MONGO_INITDB_ROOT_PASSWORD", ""),
    host=os.getenv("MONGO_HOST", "localhost"), port=os.getenv("MONGO_PORT", "27017"),
)
MONGO_DB = os.getenv("MONGO_DATABASE", "threat_intel")
APP_SECRET = os.getenv("APP_SECRET", "")
WINDOW_MINUTES = max(1, int(os.getenv("CORRELATION_WINDOW_MINUTES", "30")))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/token")
pool: ConnectionPool | None = None
mongo: MongoClient | None = None


class EventIn(BaseModel):
    source_id: UUID
    occurred_at: datetime
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    summary: str = Field(min_length=3, max_length=2000)
    payload: dict[str, Any] = Field(default_factory=dict)


class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    source_type: str = Field(min_length=2, max_length=80)
    description: str | None = None


class UserIn(BaseModel):
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern="^(admin|analyst)$")


class StatusIn(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|false_positive)$")


def db_conn():
    if pool is None:
        raise HTTPException(503, "Database is starting")
    return pool.connection()


def extract_indicators(text: str) -> list[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{3,39}\b", text):
        try:
            found.add(("ip", str(ipaddress.ip_address(candidate))))
        except ValueError:
            continue
    for domain in re.findall(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text):
        if not domain.lower().endswith((".local", ".test", ".example")):
            found.add(("domain", domain.lower().rstrip(".")))
    for kind, pattern in (("sha256", r"\b[a-fA-F0-9]{64}\b"), ("sha1", r"\b[a-fA-F0-9]{40}\b"), ("md5", r"\b[a-fA-F0-9]{32}\b")):
        for value in re.findall(pattern, text):
            found.add((kind, value.lower()))
    return sorted(found)


def current_user(token: str = Depends(oauth2)) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("missing subject")
        with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT user_id, email, role FROM users WHERE user_id=%s", (user_id,))
            user = cur.fetchone()
        if not user:
            raise ValueError("unknown user")
        return user
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired sign-in token", headers={"WWW-Authenticate": "Bearer"})


def require_admin(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator role required")
    return user


def create_token(user: dict[str, Any]) -> str:
    return jwt.encode({"sub": str(user["user_id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, APP_SECRET, algorithm="HS256")


def seed_users() -> None:
    with db_conn() as conn, conn.cursor() as cur:
        for email, role, envvar in (("admin@local.test", "admin", "BOOTSTRAP_ADMIN_PASSWORD"), ("analyst@local.test", "analyst", "BOOTSTRAP_ANALYST_PASSWORD")):
            password = os.getenv(envvar, "")
            if len(password) < 12:
                raise RuntimeError(f"Set {envvar} to a unique password with at least 12 characters")
            cur.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) ON CONFLICT (email) DO NOTHING", (email, pwd_context.hash(password), role))


@asynccontextmanager
async def lifespan(_: FastAPI):
    global pool, mongo
    if len(APP_SECRET) < 32:
        raise RuntimeError("Set APP_SECRET to a random value with at least 32 characters")
    last_error: Exception | None = None
    for _attempt in range(30):
        try:
            pool = ConnectionPool(PG_DSN, min_size=1, max_size=10, kwargs={"row_factory": dict_row}, open=True)
            pool.wait(timeout=5)
            mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            mongo.admin.command("ping")
            mongo[MONGO_DB].raw_events.create_index("event_id", unique=True)
            mongo[MONGO_DB].raw_events.create_index([("source_id", 1), ("received_at", -1)])
            seed_users()
            last_error = None
            break
        except Exception as exc:
            last_error = exc
            if pool:
                pool.close()
                pool = None
            if mongo:
                mongo.close()
                mongo = None
            time.sleep(2)
    if last_error:
        raise RuntimeError(f"Could not connect to PostgreSQL and MongoDB: {last_error}")
    yield
    if pool:
        pool.close()
    if mongo:
        mongo.close()


app = FastAPI(title="SIC Threat Intelligence Platform", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    try:
        with db_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        mongo.admin.command("ping")
        return {"status": "ok", "postgres": "connected", "mongodb": "connected"}
    except Exception as exc:
        raise HTTPException(503, f"Database health check failed: {exc}")


@app.post("/api/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT user_id,email,role,password_hash FROM users WHERE email=%s", (form.username.lower(),))
        user = cur.fetchone()
    if not user or not pwd_context.verify(form.password, user["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect", headers={"WWW-Authenticate": "Bearer"})
    return {"access_token": create_token(user), "token_type": "bearer", "email": user["email"], "role": user["role"]}


@app.get("/api/auth/me")
def me(user: dict[str, Any] = Depends(current_user)):
    return {"user_id": str(user["user_id"]), "email": user["email"], "role": user["role"]}


@app.get("/api/dashboard")
def dashboard(_: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT (SELECT count(*) FROM events) AS events, (SELECT count(*) FROM incidents WHERE status IN ('open','investigating')) AS active_incidents, (SELECT count(*) FROM indicators) AS indicators, (SELECT count(*) FROM sources WHERE enabled) AS sources")
        counts = cur.fetchone()
        cur.execute("SELECT severity,count(*) AS count FROM incidents WHERE status IN ('open','investigating') GROUP BY severity")
        counts["severity_breakdown"] = cur.fetchall()
        cur.execute("SELECT indicator_type,normalized_value,count(*) AS event_count FROM (SELECT i.type AS indicator_type,i.normalized_value,ei.event_id FROM indicators i JOIN event_indicators ei USING(indicator_id)) x GROUP BY indicator_type,normalized_value ORDER BY event_count DESC LIMIT 6")
        counts["top_indicators"] = cur.fetchall()
    return counts


@app.get("/api/sources")
def list_sources(_: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT source_id,name,source_type,description,enabled,created_at FROM sources ORDER BY name")
        return cur.fetchall()


@app.get("/api/users")
def list_users(_: dict[str, Any] = Depends(require_admin)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT user_id,email,role,created_at FROM users ORDER BY created_at")
        return cur.fetchall()


@app.post("/api/users", status_code=201)
def add_user(body: UserIn, admin: dict[str, Any] = Depends(require_admin)):
    email = body.email.lower()
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute("INSERT INTO users(email,password_hash,role) VALUES (%s,%s,%s) RETURNING user_id,email,role,created_at", (email, pwd_context.hash(body.password), body.role))
            user = cur.fetchone()
            cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'user.created','user',%s,%s)", (admin["user_id"], user["user_id"], psycopg.types.json.Jsonb({"email": email, "role": body.role})))
            return user
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "A user with that email already exists")


@app.post("/api/sources", status_code=201)
def add_source(body: SourceIn, admin: dict[str, Any] = Depends(require_admin)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute("INSERT INTO sources(name,source_type,description) VALUES (%s,%s,%s) RETURNING *", (body.name, body.source_type, body.description))
            row = cur.fetchone()
            cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'source.created','source',%s,%s)", (admin["user_id"], row["source_id"], psycopg.types.json.Jsonb({"name": body.name})))
            return row
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "A source with that name already exists")


def ingest_event(body: EventIn, actor: dict[str, Any] | None = None) -> dict[str, Any]:
    if mongo is None:
        raise HTTPException(503, "MongoDB is unavailable")
    timestamp = body.occurred_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    payload_text = body.summary + " " + str(body.payload)
    indicators = extract_indicators(payload_text)
    raw_document = {"source_id": str(body.source_id), "occurred_at": timestamp, "received_at": now, "severity": body.severity, "summary": body.summary, "payload": body.payload}
    raw_id = mongo[MONGO_DB].raw_events.insert_one(raw_document).inserted_id
    raw_doc_id = str(raw_id)
    try:
        with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT source_id FROM sources WHERE source_id=%s AND enabled=true", (body.source_id,))
            if not cur.fetchone():
                raise HTTPException(404, "Enabled event source not found")
            cur.execute("INSERT INTO events(source_id,occurred_at,severity,summary,raw_doc_id) VALUES (%s,%s,%s,%s,%s) RETURNING event_id,source_id,occurred_at,received_at,severity,summary,raw_doc_id", (body.source_id, timestamp, body.severity, body.summary, raw_doc_id))
            event = cur.fetchone()
            indicator_rows = []
            for kind, value in indicators:
                cur.execute("INSERT INTO indicators(type,normalized_value,first_seen,last_seen) VALUES (%s,%s,%s,%s) ON CONFLICT(type,normalized_value) DO UPDATE SET last_seen=GREATEST(indicators.last_seen,EXCLUDED.last_seen) RETURNING indicator_id,type,normalized_value", (kind, value, timestamp, timestamp))
                indicator = cur.fetchone()
                cur.execute("INSERT INTO event_indicators(event_id,indicator_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (event["event_id"], indicator["indicator_id"]))
                indicator_rows.append(indicator)
            cur.execute("""SELECT DISTINCT i.indicator_id,i.type,i.normalized_value,e.event_id,e.occurred_at,e.severity,e.summary,ie.incident_id
                FROM event_indicators current_ei JOIN indicators i USING(indicator_id)
                JOIN event_indicators old_ei ON old_ei.indicator_id=i.indicator_id
                JOIN events e ON e.event_id=old_ei.event_id
                LEFT JOIN incident_events ie ON ie.event_id=e.event_id
                LEFT JOIN incidents related ON related.incident_id=ie.incident_id
                WHERE current_ei.event_id=%s AND e.event_id<>%s AND e.occurred_at BETWEEN %s AND %s
                AND (ie.incident_id IS NULL OR related.status IN ('open','investigating'))
                ORDER BY e.occurred_at DESC LIMIT 50""", (event["event_id"], event["event_id"], timestamp-timedelta(minutes=WINDOW_MINUTES), timestamp+timedelta(minutes=WINDOW_MINUTES)))
            raw_matches = cur.fetchall()
            matches_by_event: dict[UUID, dict[str, Any]] = {}
            for matched in raw_matches:
                prior_event = matches_by_event.setdefault(matched["event_id"], {**matched, "shared_indicators": set()})
                prior_event["shared_indicators"].add((matched["type"], matched["normalized_value"]))
            matches = list(matches_by_event.values())
            incident_id = None
            match_reason = None
            if matches:
                existing = next((m["incident_id"] for m in matches if m["incident_id"]), None)
                if existing:
                    incident_id = existing
                else:
                    prior = matches[0]
                    cur.execute("INSERT INTO incidents(title,severity,owner_user_id) VALUES (%s,%s,%s) RETURNING incident_id", (f"Correlated activity: {body.summary[:100]}", max((body.severity, prior["severity"]), key=("low", "medium", "high", "critical").index), actor["user_id"] if actor else None))
                    incident_id = cur.fetchone()["incident_id"]
                for matched in matches:
                    indicators_text = ", ".join(f"{kind} {value}" for kind, value in sorted(matched["shared_indicators"]))
                    why = f"Shared indicator(s): {indicators_text} within {WINDOW_MINUTES} minutes"
                    cur.execute("INSERT INTO incident_events(incident_id,event_id,match_reason) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (incident_id, matched["event_id"], why))
                shared = matches[0]
                match_reason = f"Shares {shared['type']} {shared['normalized_value']} with {len(matches)} prior event(s) inside the {WINDOW_MINUTES}-minute window"
                cur.execute("INSERT INTO incident_events(incident_id,event_id,match_reason) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (incident_id, event["event_id"], match_reason))
                cur.execute("UPDATE incidents SET updated_at=now(), severity=GREATEST(severity, %s::event_severity) WHERE incident_id=%s", (body.severity, incident_id))
            if actor:
                cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'event.ingested','event',%s,%s)", (actor["user_id"], event["event_id"], psycopg.types.json.Jsonb({"indicator_count": len(indicators), "matched_count": len(matches)})))
            event["indicators"] = indicator_rows
            event["incident_id"] = incident_id
            event["match_reason"] = match_reason
            return event
    except Exception:
        mongo[MONGO_DB].raw_events.delete_one({"_id": raw_id})
        raise


@app.post("/api/events", status_code=201)
def create_event(body: EventIn, user: dict[str, Any] = Depends(current_user)):
    try:
        return ingest_event(body, user)
    except psycopg.errors.ForeignKeyViolation:
        raise HTTPException(404, "Event source not found")


@app.get("/api/events")
def list_events(_: dict[str, Any] = Depends(current_user), limit: int = Query(50, ge=1, le=200)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("""SELECT e.event_id,e.occurred_at,e.received_at,e.severity,e.summary,s.name AS source_name,
            COALESCE(json_agg(json_build_object('type',i.type,'value',i.normalized_value)) FILTER (WHERE i.indicator_id IS NOT NULL),'[]') AS indicators
            FROM events e JOIN sources s USING(source_id) LEFT JOIN event_indicators ei USING(event_id) LEFT JOIN indicators i USING(indicator_id)
            GROUP BY e.event_id,s.name ORDER BY e.occurred_at DESC LIMIT %s""", (limit,))
        return cur.fetchall()


@app.get("/api/events/{event_id}/raw")
def get_raw_event(event_id: UUID, _: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT raw_doc_id FROM events WHERE event_id=%s", (event_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Event not found")
    try:
        from bson import ObjectId
        document = mongo[MONGO_DB].raw_events.find_one({"_id": ObjectId(row["raw_doc_id"])})
    except Exception:
        document = None
    if not document:
        raise HTTPException(404, "Raw event payload not found in MongoDB")
    document["_id"] = str(document["_id"])
    return document


@app.get("/api/incidents")
def list_incidents(_: dict[str, Any] = Depends(current_user), state: str | None = None, limit: int = Query(100, ge=1, le=250)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        query = """SELECT i.incident_id,i.title,i.severity,i.status,i.created_at,i.updated_at,u.email AS owner,
            count(ie.event_id)::int AS event_count FROM incidents i LEFT JOIN users u ON u.user_id=i.owner_user_id
            LEFT JOIN incident_events ie USING(incident_id)"""
        params: list[Any] = []
        if state:
            if state not in {"open", "investigating", "resolved", "false_positive"}:
                raise HTTPException(400, "Unknown incident status")
            query += " WHERE i.status=%s"
            params.append(state)
        query += " GROUP BY i.incident_id,u.email ORDER BY i.updated_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(query, params)
        return cur.fetchall()


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: UUID, _: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT i.*,u.email AS owner FROM incidents i LEFT JOIN users u ON u.user_id=i.owner_user_id WHERE incident_id=%s", (incident_id,))
        incident = cur.fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        cur.execute("""SELECT e.event_id,e.occurred_at,e.severity,e.summary,s.name AS source_name,ie.match_reason,
          COALESCE(json_agg(json_build_object('type',i.type,'value',i.normalized_value)) FILTER (WHERE i.indicator_id IS NOT NULL),'[]') AS indicators
          FROM incident_events ie JOIN events e USING(event_id) JOIN sources s USING(source_id)
          LEFT JOIN event_indicators ei USING(event_id) LEFT JOIN indicators i USING(indicator_id)
          WHERE ie.incident_id=%s GROUP BY e.event_id,s.name,ie.match_reason ORDER BY e.occurred_at", (incident_id,))
        incident["events"] = cur.fetchall()
        return incident


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: UUID, body: StatusIn, user: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT status FROM incidents WHERE incident_id=%s FOR UPDATE", (incident_id,))
        before = cur.fetchone()
        if not before:
            raise HTTPException(404, "Incident not found")
        resolved = datetime.now(timezone.utc) if body.status in ("resolved", "false_positive") else None
        cur.execute("UPDATE incidents SET status=%s,updated_at=now(),resolved_at=%s WHERE incident_id=%s RETURNING incident_id,status,updated_at", (body.status, resolved, incident_id))
        updated = cur.fetchone()
        cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'incident.status_changed','incident',%s,%s)", (user["user_id"], incident_id, psycopg.types.json.Jsonb({"from": before["status"], "to": body.status})))
        return updated


@app.get("/api/audit")
def audit_log(_: dict[str, Any] = Depends(require_admin), limit: int = Query(100, ge=1, le=250)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT a.audit_id,a.action,a.entity_type,a.entity_id,a.details,a.created_at,u.email AS actor FROM audit_logs a LEFT JOIN users u USING(actor_user_id) ORDER BY a.created_at DESC LIMIT %s", (limit,))
        return cur.fetchall()

t_incidents(_: dict[str, Any] = Depends(current_user), state: str | None = None, limit: int = Query(100, ge=1, le=250)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        query = """SELECT i.incident_id,i.title,i.severity,i.status,i.created_at,i.updated_at,u.email AS owner,
            count(ie.event_id)::int AS event_count FROM incidents i LEFT JOIN users u ON u.user_id=i.owner_user_id
            LEFT JOIN incident_events ie USING(incident_id)"""
        params: list[Any] = []
        if state:
            if state not in {"open", "investigating", "resolved", "false_positive"}:
                raise HTTPException(400, "Unknown incident status")
            query += " WHERE i.status=%s"
            params.append(state)
        query += " GROUP BY i.incident_id,u.email ORDER BY i.updated_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(query, params)
        return cur.fetchall()


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: UUID, _: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT i.*,u.email AS owner FROM incidents i LEFT JOIN users u ON u.user_id=i.owner_user_id WHERE incident_id=%s", (incident_id,))
        incident = cur.fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        cur.execute("""SELECT e.event_id,e.occurred_at,e.severity,e.summary,s.name AS source_name,ie.match_reason,
          COALESCE(json_agg(json_build_object('type',i.type,'value',i.normalized_value)) FILTER (WHERE i.indicator_id IS NOT NULL),'[]') AS indicators
          FROM incident_events ie JOIN events e USING(event_id) JOIN sources s USING(source_id)
          LEFT JOIN event_indicators ei USING(event_id) LEFT JOIN indicators i USING(indicator_id)
          WHERE ie.incident_id=%s GROUP BY e.event_id,s.name,ie.match_reason ORDER BY e.occurred_at", (incident_id,))
        incident["events"] = cur.fetchall()
        return incident


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: UUID, body: StatusIn, user: dict[str, Any] = Depends(current_user)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT status FROM incidents WHERE incident_id=%s FOR UPDATE", (incident_id,))
        before = cur.fetchone()
        if not before:
            raise HTTPException(404, "Incident not found")
        resolved = datetime.now(timezone.utc) if body.status in ("resolved", "false_positive") else None
        cur.execute("UPDATE incidents SET status=%s,updated_at=now(),resolved_at=%s WHERE incident_id=%s RETURNING incident_id,status,updated_at", (body.status, resolved, incident_id))
        updated = cur.fetchone()
        cur.execute("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,details) VALUES (%s,'incident.status_changed','incident',%s,%s)", (user["user_id"], incident_id, psycopg.types.json.Jsonb({"from": before["status"], "to": body.status})))
        return updated


@app.get("/api/audit")
def audit_log(_: dict[str, Any] = Depends(require_admin), limit: int = Query(100, ge=1, le=250)):
    with db_conn() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT a.audit_id,a.action,a.entity_type,a.entity_id,a.details,a.created_at,u.email AS actor FROM audit_logs a LEFT JOIN users u USING(actor_user_id) ORDER BY a.created_at DESC LIMIT %s", (limit,))
        return cur.fetchall()

