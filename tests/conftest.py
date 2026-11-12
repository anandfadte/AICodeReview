"""Pytest session defaults: isolate tests from live .env API keys unless explicitly mocked/set."""

from __future__ import annotations

import os

# Keep unit & golden tests deterministic and zero-cost by default;
# tests that verify live/mocked key routing set env vars explicitly via monkeypatch.
os.environ["OPENAI_API_KEY"] = ""
os.environ["AZURE_OPENAI_KEY"] = ""
os.environ["AZURE_OPENAI_ENDPOINT"] = ""
