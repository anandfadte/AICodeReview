# ADR-02: SQLite for MVP, Postgres for Production (Config-Only Migration)

## Context
The MVP (`linetrack-reviewer`) must run out-of-the-box on any developer laptop and in GitHub Actions with zero database installation and zero Docker setup, while remaining seamlessly upgradeable to Plant Production where concurrent CI/API writes, `pgvector` embeddings, and TimescaleDB integration are required.

## Options
1. **Require Postgres 16 + Docker from Day 1:** Blocks quick local setup when Docker or PostgreSQL is not installed on developer machines or lightweight CI runners.
2. **SQLite-Specific Codebase:** Use raw `sqlite3` SQL, pragmas, and SQLite-specific DDL — requires rewriting persistence code later for Postgres.
3. **SQLite MVP + Portable SQLAlchemy Models & Alembic Migrations (`DATABASE_URL` config switch):** Default `DATABASE_URL=sqlite:///./reviewer.db`, restrict `backend/models.py` strictly to portable SQLAlchemy types (`String`, `Text`, `Integer`, `Float`, `Boolean`, `DateTime`), store JSON as `Text`, and stub memory behind `backend/reviewer/memory/search.py`.

## Decision
Adopt **Option 3**. SQLite provides zero-install MVP execution; Postgres is used in Production for concurrent writes, `pgvector`, and TimescaleDB. Migration is **config-only** because `backend/models.py` and `backend/alembic/` use strictly portable SQLAlchemy types and generic SQL.

## Consequences
- **Positive:** Fresh developer setup is `pip install -r requirements.txt && alembic upgrade head && python backend/app.py`; zero Postgres or Docker needed in MVP; exact same models, repository (`backend/store.py`), and Alembic migrations run unmodified on Postgres.
- **Negative:** MVP lacks concurrent multi-writer database locking and native `pgvector` ANN indexing (handled by `MemoryStoreStub` BM25 until production switchover).

## Reverse-if
Reverse and switch immediately to Postgres when concurrent PR/audit write volume causes SQLite lock contention or when production `pgvector` semantic indexing is required (executed via `docs/MIGRATION_TO_PRODUCTION.md`, zero business-logic rewrite).
