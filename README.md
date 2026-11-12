# linetrack-reviewer (v4 SQLite MVP)

Safety-critical, deterministic-first SDLC & OT-safety reviewer for **LineTrack** factory MES.

> **Important:** We are building the **reviewer** (`linetrack-reviewer`), not LineTrack itself.  
> Ground truth architecture & rules live in [LineTrack_Antigravity_Spec.md](LineTrack_Antigravity_Spec.md).

## Tech Stack (Zero-Install Local MVP)
- **Database:** SQLite (`sqlite:///./reviewer.db`) via portable SQLAlchemy + Alembic migrations (migrates to Postgres via config `DATABASE_URL` only).
- **Backend:** Python 3.11, FastAPI, Uvicorn, Pydantic (pure JSON REST API).
- **Frontend:** Plain HTML + Tailwind CSS CDN + Vanilla JS in a single file (`frontend/index.html`). No React, TypeScript, npm, or Vite.
- **No Docker / No Postgres install required in MVP.**

## How to Run Locally

```bash
# 1. Install dependencies (Python 3.11)
pip install -r requirements.txt

# 2. Initialize SQLite database via Alembic migrations
alembic upgrade head

# 3. Start the FastAPI backend
python backend/app.py

# 4. Open frontend/index.html via a static server (or directly in browser)
python -m http.server 3000 -d frontend
```

Then visit `http://localhost:3000` (backend runs at `http://localhost:8000`).

## Frozen API Contract
- `POST /api/review`
- `GET /api/runs/{id}`
- `GET /api/findings?run_id=`
- `GET /api/sarif?run_id=`
- `GET /api/report?run_id=`
