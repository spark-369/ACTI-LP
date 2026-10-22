# ACTI-LP — Automated Cyber Threat Intelligence & Log Parser

A fully self-hosted SIEM-style log analysis service. Raw log lines are embedded
and matched against a per-tenant vector store, then classified by
**Qwen2.5-0.5B-Instruct** under **Outlines** constrained decoding, so every
response is valid JSON conforming to a versioned schema. No inference traffic
leaves the host.

| | |
|---|---|
| **Backend** | Python 3.11 · FastAPI · SQLAlchemy · Celery |
| **LLM** | Qwen/Qwen2.5-0.5B-Instruct (CPU, in-process) |
| **Structured output** | Outlines ≥ 1.0 (`outlines.Generator`) |
| **Vector store** | ChromaDB `PersistentClient` (embedded, no server) |
| **Frontend** | React 18 · Vite · Zustand · Tailwind · Recharts, served by `serve` |
| **Storage** | PostgreSQL · Redis (broker + Streams) · local ChromaDB |
| **Auth** | JWT (access + refresh) with tenant-scoped RBAC |
| **Packaging** | Dockerfile + manual `docker run`; images pushed to Docker Hub |

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [Prerequisites](#2-prerequisites)
3. [Quick start (Docker)](#3-quick-start-docker)
4. [Local development](#4-local-development)
5. [Architecture](#5-architecture)
6. [Configuration](#6-configuration)
7. [API reference](#7-api-reference)
8. [Output schema and prompt contract](#8-output-schema-and-prompt-contract)
9. [CI/CD](#9-cicd)
10. [Operations](#10-operations)
11. [Troubleshooting](#11-troubleshooting)
12. [Known limitations](#12-known-limitations)
13. [Licence](#13-licence)

---

## 1. What it does

Given a single raw log line — firewall, IDS, syslog, EDR or application log — the
service returns a structured verdict:

```json
{
  "is_malicious": true,
  "attack_type": "brute_force",
  "severity": "high",
  "mitre_tactic": "TA0006 - Credential Access",
  "iocs": ["185.220.101.45"],
  "confidence": 0.8,
  "summary": "Repeated failed RDP logins for an invalid user from a single source."
}
```

Alerts are persisted per tenant, surfaced in a React dashboard, and triaged by
analysts through acknowledge/close workflows. Every mutation is written to an
append-only audit trail.

**Design priorities, in order:** determinism of output format → data isolation →
operability on commodity CPU hardware. Semantic accuracy is explicitly *not*
guaranteed; see [Known limitations](#12-known-limitations).

---

## 2. Prerequisites

* Docker 20.10+ (the only requirement for the containerised path)
* For local development: Python 3.11, Node 20, a reachable PostgreSQL and Redis
* ~2 GB free disk for the model cache, ~4 GB RAM for the API container


---

## 3. Quick start (Docker)

### 3.1 Build the images

```bash
git clone https://github.com/org/acti-lp.git
cd acti-lp

# The API build context is the REPO ROOT, not apps/api:
# the image needs both apps/api/ and the repo-level ml/ prompt tree.
docker build -f apps/api/Dockerfile -t "$USER/acti-lp-api:latest" .
docker build -t "$USER/acti-lp-web:latest" apps/web
```

The API image pre-downloads Qwen2.5-0.5B and the local embedder at build time,
reading `HF_MODEL_ID` / `EMBEDDER_MODEL` from the baked `.env`. The first build
therefore needs network access and takes several minutes.

### 3.2 Start the stack

```bash
docker network create actilp-net

docker run -d --name actilp-postgres --network actilp-net \
  -e POSTGRES_DB=actilp -e POSTGRES_USER=actilp -e POSTGRES_PASSWORD=change-me \
  -v pg_data:/var/lib/postgresql/data --restart unless-stopped postgres

docker run -d --name actilp-redis --network actilp-net \
  --restart unless-stopped redis:alpine

docker run -d --name actilp-api --network actilp-net \
  -v hf_cache:/app/.cache/huggingface -v chroma_data:/app/.chroma \
  -p 8080:8080 --restart unless-stopped "$USER/acti-lp-api:latest"

docker run -d --name actilp-worker --network actilp-net \
  -v hf_cache:/app/.cache/huggingface -v chroma_data:/app/.chroma \
  --restart unless-stopped "$USER/acti-lp-api:latest" \
  celery -A app.workers worker --loglevel=info --concurrency=1

docker run -d --name actilp-web --network actilp-net \
  -p 3000:3000 --restart unless-stopped "$USER/acti-lp-web:latest"
```

No `--env-file` is required: `apps/api/.env` is copied into the image at build
time. Only the model cache and Chroma data directories are mounted.

> **Worker concurrency must stay at 1.** Embedded ChromaDB is not safe for
> concurrent writers. Running more than one worker process risks index corruption.

### 3.3 Verify

```bash
curl -s localhost:8080/healthz | python -m json.tool
# expect: status=ok, postgres=ok, redis=ok, chroma=ok, model=ok|not-loaded
```

Open <http://localhost:3000> and sign in with the bootstrap administrator from
[§6.3](#63-bootstrap-administrator):

```
admin@actilp.local / Admin123!
```

> `model: "not-loaded"` is normal until the first parse request; the weights load
> lazily unless `HF_PRELOAD_ON_STARTUP=true`.

### 3.4 Supplying a container `.env`

The baked `.env` holds **development** values (`localhost` for Postgres/Redis).
For a container deployment, point those at the service names. The image
overrides the two container-local paths via `ENV`, which always beat `.env`:

| Variable | Container value | Source |
|---|---|---|
| `HF_HOME` | `/app/.cache/huggingface` | Dockerfile `ENV` |
| `CHROMA_PATH` | `/app/.chroma` | Dockerfile `ENV` |
| `POSTGRES_HOST` | `actilp-postgres` | must be set in `.env` or `-e` |
| `REDIS_URL` | `redis://actilp-redis:6379/0` | must be set in `.env` or `-e` |

---

## 4. Local development

```bash
# 1. Dependencies, published on localhost
docker run -d --name actilp-pg-dev -p 5432:5432 \
  -e POSTGRES_DB=actilp -e POSTGRES_USER=actilp -e POSTGRES_PASSWORD=change-me postgres
docker run -d --name actilp-redis-dev -p 6379:6379 redis:alpine

# 2. Backend — .env already targets localhost, so no overrides needed.
#    Run from apps/api: pydantic-settings resolves env_file relative to the CWD.
cd apps/api
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080

# 3. Frontend (Vite proxies /api to localhost:8080)
cd apps/web
npm install
npm run dev
```

The SPA is at <http://localhost:3000>; interactive API docs at
<http://localhost:8080/docs>.

### 4.1 Running the tests

Tests require **no** database, Redis or model download — SQLite and the LLM are
stubbed.

```bash
cd apps/api

PYTHONPATH=. pytest ../../tests/unit -v
PYTHONPATH=. pytest ../../tests/integration -v
```

`PYTHONPATH=.` and running from `apps/api` are both required: the former makes
`app` importable, the latter lets `pydantic-settings` find `.env`.

### 4.2 Linting

```bash
ruff check apps/api/app          # backend (config in ruff.toml)
cd apps/web && npm run lint      # frontend (eslint, zero warnings tolerated)
```


---

## 5. Architecture

```
Data sources (firewall / IDS / syslog / EDR / application logs)
        │  Filebeat · Fluent Bit · syslog-ng   (XADD)
        ▼
Redis Streams ──► Celery worker (--concurrency=1)
        │                 │
        │                 ├── local ChromaDB  (PersistentClient, /app/.chroma)
        │                 └── Qwen2.5-0.5B-Instruct + Outlines (CPU)
        ▼                 ▼
              PostgreSQL (users · alerts · audit)
        ▲
FastAPI (JWT + RBAC, REST /api/v1)  ◄──  React SPA served by `serve` on :3000
```

### 5.1 Repository layout

```
acti-lp/
├── apps/
│   ├── api/                       # FastAPI + Celery backend
│   │   ├── app/
│   │   │   ├── main.py            # app, /healthz, CORS, lifespan
│   │   │   ├── db.py              # SQLAlchemy engine / session
│   │   │   ├── core/              # config.py, security.py, logging.py
│   │   │   ├── models/            # Tenant, User, Alert, AuditLog
│   │   │   ├── schemas/           # Pydantic + Outlines output schema
│   │   │   ├── api/v1/            # auth, alerts, parse, dashboard, users, audit
│   │   │   ├── services/          # chroma_local_svc, hf_outlines_svc, embedder,
│   │   │   │                      # parser, ingest, audit, bootstrap
│   │   │   └── workers/           # Celery app + tasks
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── .env                   # committed, baked into the image
│   └── web/                       # React + Vite + Zustand + Tailwind + Recharts
│       ├── src/{api,components,hooks,pages,store}
│       ├── Dockerfile             # build → `serve`
│       └── .env                   # VITE_API_URL (baked at build time)
├── ml/
│   ├── prompts/{system.txt,parse_user.txt}
│   ├── schemas/log_parse.schema.json
│   └── manifest.json
├── tests/
│   ├── unit/                      # schemas, JWT/RBAC, parser heuristics
│   └── integration/               # TestClient + SQLite, model & Chroma stubbed
├── .github/workflows/{ci.yml,build-push.yml}
├── pytest.ini
├── ruff.toml
└── README.md
```

### 5.2 Request lifecycle

1. `POST /api/v1/parse` — or a Redis Stream entry consumed by the worker —
   receives one raw log line.
2. `chroma_local_svc.search()` retrieves the nearest `RAG_TOP_K` (default **10**)
   historical logs for the tenant from the `threat_<tenant_id>` collection.
3. `hf_outlines_svc.parse_log()` renders the chat prompt from `ml/prompts/*` and
   runs the Outlines generator constrained to `LogParseResult`.
4. `parser.parse_and_persist()` writes the alert, then indexes the log vector
   back into Chroma for future retrieval.
5. `audit.record()` appends an immutable audit row.

### 5.3 Retrieval window

Chroma returns neighbours nearest-first, so the closest few carry nearly all the
signal. A large window mostly adds prompt tokens — and small models lose
instruction-following as prompts grow. Two independent caps apply:

| Limit | Default | Effect |
|---|---|---|
| `RAG_TOP_K` | 10 | Documents fetched from Chroma |
| `RAG_CONTEXT_MAX_CHARS` | 16,000 | Characters of history rendered into the prompt |

> **These defaults are a considered starting point, not a measured optimum.**
> Neither value has been validated against a labelled corpus. If you change them,
> score accuracy on a labelled log sample first.

### 5.4 Graceful degradation

If the model cannot be loaded — weights unavailable, OOM, no network on first
boot — the service falls back to a deterministic regex signature parser and
records `parser_mode = "fallback"` on the alert. The API stays available and the
degradation is visible in `/healthz` and in the alert record itself.

The fallback covers **11** attack categories (the original core set) and is
strictly weaker than the model. A rising `fallback` rate in your alerts table is
an incident signal, not a benign detail.

---

## 6. Configuration

### 6.1 Where configuration lives

`apps/api/.env` — committed to the repository and baked into the image at build
time. Real environment variables take precedence over the file.

`apps/api/app/core/config.py` defines the typed `Settings` model. Every key below
is validated at import; a malformed value fails fast at startup rather than
mid-request.

### 6.2 Variable reference

| Variable | Default (dev) | Description |
|---|---|---|
| `POSTGRES_DB` / `_USER` / `_PASSWORD` | `actilp` / `actilp` / `change-me` | Credentials |
| `POSTGRES_HOST` / `_PORT` | `localhost` / `5432` | Use `actilp-postgres` in Docker |
| `REDIS_URL` | `redis://localhost:6379/0` | Celery broker, result backend, Streams |
| `STREAM_NAME` / `STREAM_GROUP` | `actilp:raw_logs` / `actilp-workers` | Ingestion stream + consumer group |
| `JWT_SECRET` | dev placeholder | **Must be rotated for any non-local use** |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm |
| `ACCESS_TOKEN_TTL_MINUTES` | `60` | Access-token lifetime |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | Refresh-token lifetime |
| `CHROMA_PATH` | `./.chroma` | Vector store location (`/app/.chroma` in Docker) |
| `RAG_TOP_K` | `10` | Retrieval window — see [§5.3](#53-retrieval-window) |
| `RAG_CONTEXT_MAX_CHARS` | `0` (→ 16,000) | History characters in the prompt |
| `HF_MODEL_ID` | `Qwen/Qwen2.5-0.5B-Instruct` | Model identifier |
| `HF_DEVICE` | `cpu` | `cpu` or `cuda` |
| `HF_HOME` | `$HOME/.cache/huggingface` | Model cache (must be an absolute path) |
| `HF_MAX_NEW_TOKENS` | `512` | Decoding cap; too low truncates JSON |
| `HF_PRELOAD_ON_STARTUP` | `false` | Load weights during boot instead of lazily |
| `EMBEDDER_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Local embedder (in-process) |
| `ML_PROMPT_DIR` | empty (auto-detect) | Override for `ml/prompts` |
| `APP_ENV` | `development` | `development` \| `production` |
| `LOG_LEVEL` | `debug` | `debug` \| `info` \| `warning` \| `error` |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated browser origins |
| `BOOTSTRAP_ADMIN_EMAIL` | `admin@actilp.local` | Seeded administrator |
| `BOOTSTRAP_ADMIN_PASSWORD` | `Admin123!` | Seeded administrator password |

### 6.3 Bootstrap administrator

On startup, `bootstrap.bootstrap()` creates the schema, seeds the `default`
tenant, and creates the administrator **if it does not already exist**. Changing
`BOOTSTRAP_ADMIN_PASSWORD` later does **not** change an existing account's
password — rotate it through the API or directly in the database.

### 6.4 Security note

`.env` is baked into the image layers. Treat every published image as containing
its secrets: keep the registry **private**, rotate `JWT_SECRET` and the bootstrap
password before production use, and never push these images to a public
repository. This is a deliberate trade for operational simplicity in
single-host deployments; it is not suitable for distribution.


---

## 7. API reference

Base path `/api/v1`. Interactive OpenAPI docs at `/docs`.

### 7.1 Authentication

OAuth2 password flow. Send `Authorization: Bearer <access_token>` on every
authenticated call.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/healthz` | public | Dependency status: Postgres, Redis, Chroma, model |
| `POST` | `/auth/login` | public | Form-encoded login (Swagger UI compatible) |
| `POST` | `/auth/login/json` | public | JSON login: `{email, password}` |
| `POST` | `/auth/refresh` | public | Rotate refresh token → new pair |
| `GET` | `/auth/me` | any | Current user |

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login/json \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@actilp.local","password":"Admin123!"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

### 7.2 Parsing

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/parse` | analyst+ | Synchronous analysis; `async_mode: true` returns a `task_id` |
| `POST` | `/parse/batch` | analyst+ | Queue up to 100 log lines; returns task IDs |
| `GET` | `/parse/context` | any | Similar historical logs for a query string |

```bash
curl -s -X POST localhost:8080/api/v1/parse \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"raw_log":"failed password for invalid user administrator from 185.220.101.45"}'
```

### 7.3 Alerts

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/alerts` | any | Filter by `severity`, `status`, `malicious`, `search`; paginated |
| `GET` | `/alerts/{id}` | any | Alert detail |
| `POST` | `/alerts/{id}/acknowledge` | analyst+ | Mark acknowledged |
| `POST` | `/alerts/{id}/close` | analyst+ | Close |

### 7.4 Dashboard, users, audit

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/dashboard/stats?days=N` | any | Totals, severity buckets, attack types, daily timeline (`days` 1–90) |
| `GET` | `/users` | admin | List tenant users |
| `POST` | `/users` | admin | Create user (`role`: `admin`\|`analyst`\|`viewer`) |
| `DELETE` | `/users/{id}` | admin | Deactivate (soft delete) |
| `GET` | `/audit` | admin | Append-only audit trail |

### 7.5 RBAC and tenant isolation

| Role | Permissions |
|---|---|
| `admin` | Full access, including user management and audit |
| `analyst` | Read, parse, acknowledge/close |
| `viewer` | Read-only |

Every query is scoped by the `tid` claim in the JWT. A token issued for one
tenant cannot read another tenant's alerts, even with an `admin` role — tenant
isolation is enforced in the query layer, not merely in the route guard.

### 7.6 Error semantics

| Status | Meaning |
|---|---|
| `401` | Missing, expired or invalid token |
| `403` | Authenticated but role/tenant insufficient |
| `409` | State conflict (e.g. acknowledging a closed alert) |
| `422` | Request body failed schema validation |
| `500` | Unhandled error; correlates with the `x-request-id` response header |

Login deliberately avoids `422` on malformed input — a bad email returns `401`,
so the endpoint does not leak field-level validation detail.


---

## 8. Output schema and prompt contract

### 8.1 Schema

`ml/schemas/log_parse.schema.json` (version 2) mirrors
`app.schemas.LogParseResult`.

| Field | Type | Notes |
|---|---|---|
| `is_malicious` | bool | Required |
| `attack_type` | enum (100) | Closed vocabulary; `none` for benign |
| `severity` | enum (4) | `low` \| `medium` \| `high` \| `critical` |
| `mitre_tactic` | enum (12) or `""` | Canonical `TAxxxx - Name` form |
| `iocs` | list[str] | Verbatim indicators, max 10 |
| `confidence` | enum of 0.1-step strings | String so the grammar can enforce it; exposed as float via `confidence_value` |
| `summary` | str | One or two sentences |

`confidence` is a **string** enum (`"0.1"` … `"1.0"`) because grammar backends do
not enforce numeric `minimum`/`maximum` — a real observed failure was the model
emitting `100` and Pydantic rejecting it, silently dropping every parse into the
fallback. The API and database expose it as a float.

### 8.2 Constrained decoding and repair

Outlines guarantees the *shape* of the output, not the model's cooperation across
every backend. Values that still arrive malformed are repaired rather than
rejected, because one bad field would otherwise discard an entire analysis:

| Model emitted | Stored as |
|---|---|
| `"SQL Injection"`, `"SQL-Injection"` | `sql_injection` |
| `"XSS"` | `cross_site_scripting` |
| `"DDoS"` | `distributed_denial_of_service` |
| `"SSRF"` / `"XXE"` / `"SSTI"` | `server_side_request_forgery` / `xml_external_entity` / `server_side_template_injection` |
| `"cryptojacking"` | `cryptominer` |
| `"unknown"`, `"benign"`, anything unmapped | `none` |
| `mitre_tactic: "TA0006"` / `"credential access"` | `TA0006 - Credential Access` |
| `mitre_tactic: null` or an invented tactic | `""` |

The original 11 categories keep their exact spelling and remain first in the
enum, so existing `alerts` rows stay valid after the expansion to 100.

> **Schema vs. prompt vocabulary.** The schema accepts 100 values; the prompt
> advertises a ~30-label shortlist. A 0.5B model discriminates better across a
> short list, and the full enum costs nothing when it is not in the prompt. Tests
> enforce that the prompt never names a value the enum rejects, and that the
> shortlist stays under 40.

### 8.3 Prompt construction

| File | Purpose |
|---|---|
| `ml/prompts/system.txt` | Role, severity/vocabulary constraints, MITRE list, worked JSON example |
| `ml/prompts/parse_user.txt` | History block + the log between explicit markers |

Guarantees enforced in `build_prompt()`:

* **Literal substitution** (`_fill`), never `str.format` — a `{` or `}` inside a
  log line cannot crash or corrupt the prompt.
* **Delimited untrusted data** — the log sits between
  `=== BEGIN/END UNTRUSTED RAW LOG ===`.
* **Whitespace collapsed, capped at 2,000 chars** (`MAX_LOG_CHARS`) so a
  multi-line payload cannot forge the end-of-log delimiter.
* **Native chat template** — when a tokenizer is loaded, its
  `apply_chat_template` is used so Qwen's special tokens match training exactly;
  otherwise a literal `<|im_start|>…` fallback is used.


`attack_type` is a **100-value closed enum** and `mitre_tactic` is a closed
12-value enum, so constrained decoding cannot emit an invalid category. The
grammar guarantees the *shape*, not the model's cooperation across backends, so
values that still come back malformed are repaired rather than rejected:

| Model emitted | Stored as |
|---|---|
| `"SQL Injection"`, `"SQL-Injection"` | `sql_injection` |
| `"XSS"` | `cross_site_scripting` |
| `"DDoS"` | `distributed_denial_of_service` |
| `"SSRF"` / `"XXE"` / `"SSTI"` | `server_side_request_forgery` / `xml_external_entity` / `server_side_template_injection` |
| `"cryptojacking"` | `cryptominer` |
| `"unknown"`, `"benign"`, anything unmapped | `none` |
| `mitre_tactic: "TA0006"` / `"credential access"` | `TA0006 - Credential Access` |
| `mitre_tactic: null` / an invented tactic | `""` |

The original 11 categories keep their exact spelling and stay first in the
enum, so rows already in the `alerts` table remain valid. `test_attack_type_enum_is_100`,
`test_prompt_lists_every_attack_type` and `test_schema_json_enum_matches_pydantic`
keep the enum, the prompt and the JSON schema from drifting apart.

This matters because a single unparsable field sends the whole parse to the
regex fallback (`parser_mode="fallback"`), which is far less accurate than the
model.

### Prompt contract

* `ml/prompts/system.txt` — role, the allowed `attack_type` vocabulary, the
  closed MITRE tactic list, and one worked JSON example (a 0.5B model needs to
  *see* the target shape, not just be told about it).
* `ml/prompts/parse_user.txt` — history block plus the log wrapped in
  `=== BEGIN/END UNTRUSTED RAW LOG ===` markers.
* Substitution is literal (`_fill`), never `str.format`, so `{`/`}` inside a
  log line cannot crash or corrupt the prompt.
* The log is whitespace-collapsed and capped at `MAX_LOG_CHARS` (2000) so a
  multi-line payload cannot forge the end-of-log delimiter or crowd out the
  instructions.
* When a tokenizer is loaded, `build_prompt` uses its `apply_chat_template` so
  Qwen's special tokens match training exactly; otherwise it falls back to the
  literal `<|im_start|>…` format.

---

## 9. CI/CD

| Workflow | Trigger | Steps |
|---|---|---|
| `ci.yml` | push, pull_request | `ruff check`; unit tests; `npm run lint` + `npm run build`; Trivy filesystem scan |
| `build-push.yml` | push to `main` | Build `acti-lp-api` and `acti-lp-web`, push to Docker Hub, gate on Trivy HIGH/CRITICAL |

Required repository secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`.

The API image is built with `context: .` and `file: apps/api/Dockerfile` because
it needs the repo-level `ml/` tree. The web image uses `context: apps/web`.

---

## 10. Operations

### 10.1 Health

`GET /healthz` reports each dependency independently. A degraded dependency is
reported in the payload rather than failing the whole check, so a Redis outage
does not make the API appear entirely down.

`GET /healthz/ready` additionally reports the embedder — useful before sending
bulk traffic, since the embedder loads lazily.

### 10.2 Logs

Structured JSON on stdout via `app.core.logging`. Each request carries an
`x-request-id` (echoed in the response header). Uvicorn's own loggers are routed
through the same formatter, with `chromadb` and `httpx` pinned to `WARNING`.

```bash
docker logs -f actilp-api --tail 100
docker logs -f actilp-worker --tail 100
```

### 10.3 Audit trail

`audit_log` is append-only at two levels: the service exposes no update/delete,
and `bootstrap` installs PostgreSQL rules that turn `UPDATE`/`DELETE` into no-ops.

### 10.4 Backup

| Volume | Contents | Priority |
|---|---|---|
| `pg_data` | Users, alerts, audit | **Critical** |
| `chroma_data` | Vector index (rebuildable from alerts, not cheaply) | High |
| `hf_cache` | Model weights (~1 GB, re-downloadable) | Low |

```bash
docker run --rm -v acti-lp_pg_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/pg_data-$(date +%F).tar.gz -C /data .
```

### 10.5 Sizing (CPU only)

| Component | Dev | Prod |
|---|---|---|
| API + worker (Qwen 0.5B) | 2 vCPU / 4 GB | 4 vCPU / 8 GB |
| PostgreSQL | 2 vCPU / 4 GB | 4 vCPU / 8 GB |
| Redis | 1 vCPU / 2 GB | 2 vCPU / 4 GB |
| Web (`serve`) | 1 vCPU / 512 MB | 2 vCPU / 1 GB |

### 10.6 SLO targets

| Metric | Target | Note |
|---|---|---|
| Schema conformance | > 99.9 % | Guaranteed by constrained decoding, except truncated responses |
| Availability | > 99.5 % | Single host; see [§12](#12-known-limitations) |
| P95 latency | < 3 s | Aspirational on 2 vCPU; **unverified** |

---

## 11. Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `docker build` fails: `ml: not found` | Built with `context: apps/api` | Use `-f apps/api/Dockerfile ... .` ([§3.1](#31-build-the-images)) |
| `/healthz` shows `postgres: error` | `POSTGRES_HOST=localhost` inside a container | Set `actilp-postgres` |
| `/healthz` shows `redis: error` | Same, for Redis | Set `redis://actilp-redis:6379/0` |
| Sidebar shows "Degraded" but API is up | SPA probing the wrong origin | Confirm `apps/web/.env` `VITE_API_URL` points at the API |
| Every alert `parser_mode="fallback"` | Model failed to load | `docker logs actilp-api`; check `HF_HOME` is writable and weights cached |
| `invalid_model_json` errors | `HF_MAX_NEW_TOKENS` too low | Raise it (default 512) |
| `pydantic.ValidationError` for missing settings | Running outside `apps/api` | `cd apps/api` first — `env_file` is CWD-relative |
| `ModuleNotFoundError: app` | `PYTHONPATH` not set | `PYTHONPATH=. pytest ...` |
| CORS error on login | Origin not listed | Add it to `CORS_ORIGINS` |

---

## 12. Known limitations

1. **Model accuracy is not guaranteed.** A 0.5B model has a limited ceiling on
   classifying free-form SOC logs. Outlines guarantees *well-formed* output, not
   *correct* output. Keep a human review queue for critical severity.
2. **No accuracy benchmark exists in this repository.** `RAG_TOP_K`,
   `RAG_CONTEXT_MAX_CHARS` and the prompt vocabulary are reasoned defaults, not
   measured optima. Before tuning them, score against a labelled sample of real
   logs (~150–200 rows, ~30 % benign) and track malicious-vs-benign F1 and
   `attack_type` accuracy separately.
3. **The fallback parser is a narrow safety net.** It covers 11 of the 100
   schema categories, so quality drops sharply when the model is unavailable.
4. **Embedded ChromaDB is single-host.** Not safe for concurrent writers and
   does not scale horizontally. The worker must run `--concurrency=1`. Migrate to
   Chroma server mode to scale out.
5. **Secrets are baked into images.** Acceptable only for a private registry in
   a single-host deployment.
6. **Single-host SPOF.** Mitigated by `--restart unless-stopped` and volume
   backups, not eliminated.
7. **Multi-line logs are flattened.** Whitespace is collapsed and content is
   capped at 2,000 characters, so stack traces and multi-line dumps are truncated
   by design. Raise `MAX_LOG_CHARS` if that matters more than injection safety.
8. **`none` is ambiguous.** It means both "benign" and "malicious but
   uncategorised". Novel attack types collapse into `none`; there is no separate
   `unclassified` bucket yet.
9. **Retrieval distances are discarded.** `chroma_local_svc.search` returns
   documents but not cosine distances, so the only genuine novelty signal in the
   system is currently unused.

---

## 13. Licence

Internal / proprietary. Not for redistribution. These images embed secrets — do
not publish them.


