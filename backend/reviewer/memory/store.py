"""MVP Memory Stub — portable SQLite table + pure-Python BM25/term search (NO pgvector).

Behind a clean interface (`MemoryBackend`) so Production can swap in a pgvector
implementation without changing agent or orchestrator code.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.store import ReviewerStore

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


@dataclass
class MemoryItem:
    id: str
    memory_type: str  # semantic | episodic | procedural
    title: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


class MemoryStoreStub:
    """SQLite-backed memory stub with lightweight pure-Python BM25 scoring (zero pgvector)."""

    def __init__(self, db_url: str | None = None, check_catalogue_path: str | Path | None = None, persist: bool = False):
        self.entries: list[MemoryItem] = []
        self._repo = ReviewerStore(db_url=db_url, auto_create=True) if persist else None
        self._load_check_catalogue(check_catalogue_path)
        self._seed_procedural_recipes()

    def _load_check_catalogue(self, path: str | Path | None = None) -> None:
        candidates = [Path(path)] if path else []
        candidates.extend([Path.cwd() / "checks" / "check_catalogue.json", Path(__file__).resolve().parents[3] / "checks" / "check_catalogue.json"])
        for c in candidates:
            if c.is_file():
                try:
                    for item in json.loads(c.read_text(encoding="utf-8")):
                        cid = item.get("id", "")
                        txt = f"{cid} {item.get('name', '')} {' '.join(item.get('standards', []))} {item.get('method', '')}"
                        self.add_entry(f"sem:{cid}", "semantic", f"{cid}: {item.get('name', '')}", txt, item)
                    return
                except Exception:
                    break

    def _seed_procedural_recipes(self) -> None:
        recipes = [
            ("proc:ot-clamp", "OT PLC Write Clamp Recipe", "Enforce allow-list + clamp (`not in range`) + @require_role + check_interlock() + audit_log."),
            ("proc:oee-safe", "OEE Safe Math Recipe", "Guard denominators against 0 and clamp Availability, Performance, Quality, OEE to [0, 1]."),
            ("proc:genealogy", "IATF 16949 Lot Genealogy Recipe", "Require non-null lot_id, machine, order_id and write audit log on every part save."),
            ("proc:ask-delim", "Ask LineTrack Prompt Isolation Recipe", "Filter logs by user_plant and user_role, wrap in <UNTRUSTED_DATA> delimiters."),
        ]
        for eid, title, body in recipes:
            self.add_entry(eid, "procedural", title, body)

    def add_entry(self, entry_id: str, memory_type: str, title: str, content: str, metadata: dict[str, Any] | None = None) -> None:
        item = MemoryItem(entry_id, memory_type, title, content, metadata or {})
        self.entries.append(item)
        if self._repo is not None:
            self._repo.upsert_memory_entry(entry_id, memory_type, title, content, metadata)

    def add_episodic(self, run_id: str, summary: str, metadata: dict[str, Any] | None = None) -> None:
        self.add_entry(f"epi:{run_id}:{len(self.entries)}", "episodic", f"Run {run_id}", summary, metadata)

    def search(self, query: str, memory_type: str | None = None, top_k: int = 5) -> list[MemoryItem]:
        pool = [e for e in self.entries if memory_type is None or e.memory_type == memory_type]
        if not pool or not query.strip():
            return pool[:top_k]

        q_tokens = _tokenize(query)
        docs_tokens = [_tokenize(f"{e.title} {e.content}") for e in pool]
        n_docs = len(docs_tokens)
        avg_dl = sum(len(d) for d in docs_tokens) / max(1, n_docs)

        df: Counter[str] = Counter()
        for dt in docs_tokens:
            for tok in set(dt):
                df[tok] += 1

        k1, b = 1.5, 0.75
        scored: list[tuple[float, MemoryItem]] = []
        for entry, dt in zip(pool, docs_tokens):
            tf = Counter(dt)
            dl = len(dt)
            score = 0.0
            for qt in q_tokens:
                if qt not in tf:
                    continue
                idf = math.log((n_docs - df[qt] + 0.5) / (df[qt] + 0.5) + 1.0)
                freq = tf[qt]
                denom = freq + k1 * (1.0 - b + b * (dl / max(1.0, avg_dl)))
                score += idf * ((freq * (k1 + 1.0)) / max(1e-9, denom))
            scored.append((score, entry))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [item for _, item in scored[:top_k]]
