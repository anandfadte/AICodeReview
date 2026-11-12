# Migrating LineTrack Reviewer from SQLite (MVP) to Postgres (Production)

1. Change `DATABASE_URL` to `postgresql://user:pass@host:5432/reviewer` (and install `psycopg2-binary` in production).
2. Run `alembic upgrade head` against the Postgres target to create all tables (`pr_runs`, `audits`, `findings`, `suppressions`, `memory_entries`).
3. No code change is needed because `backend/models.py` uses ONLY portable SQLAlchemy column types (`String`, `Text`, `Integer`, `Float`, `Boolean`, `DateTime`) with JSON serialized in `Text` — zero `JSONB`, `ARRAY`, `pgvector`, or SQLite-only types/pragmas.
