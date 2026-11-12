# Production Migration Plan (SQLite MVP -> Plant Production Postgres)

> **Status:** Documented for Production rollout — **NOT implemented in MVP**.  
> Backend APIs (`backend/app.py`), repository (`backend/store.py`), models (`backend/models.py`), checks, Judge, and guardrails require **zero code rewrite**.

## Exact Migration Steps

1. **Switch `DATABASE_URL` via environment variable:**
   Change `DATABASE_URL` from `sqlite:///./reviewer.db` to:
   `postgresql://user:pass@host:5432/reviewer`

2. **Install production database drivers (Production environment only):**
   ```bash
   pip install psycopg2-binary pgvector
   ```

3. **Run existing Alembic migrations (`alembic upgrade head`):**
   The exact same `backend/alembic/versions/0001_initial_tables.py` migration executes unmodified on Postgres.
   - **Portable types verification (`backend/models.py`):** Uses ONLY `String`, `Text`, `Integer`, `Float`, `Boolean`, and `DateTime` (with JSON serialized as `Text`).
   - **Postgres-breaking / Postgres-only types present in MVP:** **NONE** (zero `JSONB`, `ARRAY`, `pgvector` columns, `ILIKE`, or SQLite-only `AUTOINCREMENT`/pragma hacks).

4. **Swap Memory Stub for `pgvector` behind unchanged interface:**
   Replace `MemoryStoreStub` inside `backend/reviewer/memory/search.py` (`get_memory_backend()`) with a `pgvector`-backed adapter implementing the exact same `search(query, memory_type, top_k)` protocol. Agents and orchestrator remain unchanged.

5. **Add `docker-compose.yml` (Production only, NOT in MVP):**
   Add `postgres` (`pgvector/pgvector:pg16`) and `app` (`backend/app.py`) + static `frontend` service in `docker-compose.yml`. Backend code does NOT change to run inside Docker — only `DATABASE_URL` and `AZURE_OPENAI_KEY` env vars.

6. **Switch GitHub Actions runner to self-hosted inside plant network:**
   Update `.github/workflows/review.yml` from `runs-on: ubuntu-latest` to `runs-on: self-hosted` so source code and Node-RED flows stay inside the plant network.

7. **Serve `frontend/index.html` (or future React UI) against frozen `/api/*` endpoints:**
   `frontend/index.html` requires zero changes when served via Nginx/static server. If UI is later migrated to React, it consumes the exact same frozen REST endpoints (`POST /api/review`, `GET /api/runs/{id}`, `GET /api/findings?run_id=`, `GET /api/sarif?run_id=`, `GET /api/report?run_id=`).
