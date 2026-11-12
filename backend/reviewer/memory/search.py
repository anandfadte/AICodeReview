"""Stable memory search interface (MVP SQLite BM25 stub; Production swaps in pgvector behind same API)."""

from __future__ import annotations

from typing import Protocol

from backend.reviewer.memory.store import MemoryItem, MemoryStoreStub


class MemorySearchBackend(Protocol):
    def search(self, query: str, memory_type: str | None = None, top_k: int = 5) -> list[MemoryItem]: ...


def get_memory_backend(db_url: str | None = None) -> MemorySearchBackend:
    """Return MVP SQLite BM25 stub (Production overrides with pgvector implementation)."""
    return MemoryStoreStub(db_url=db_url, persist=False)
