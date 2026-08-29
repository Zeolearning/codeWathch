from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass
class CodeWatchConfig:
    repo_path: str = ""
    model: str = "gpt-4o-mini"
    openai_api_key: str = ""
    openai_base_url: str = ""
    langsmith_api_key: str = ""
    langsmith_project: str = "code-watch"
    langsmith_tracing: bool = True
    index_cache_dir: str = ""
    max_read_bytes: int = 1_500_000

    @classmethod
    def from_env(cls, **overrides: str) -> CodeWatchConfig:
        c = cls(
            repo_path=os.getenv("CODE_WATCH_REPO", ""),
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            openai_base_url=os.getenv("OPENAI_BASE_URL", ""),
            langsmith_api_key=os.getenv("LANGSMITH_API_KEY", ""),
            langsmith_project=os.getenv("LANGSMITH_PROJECT", "code-watch"),
            langsmith_tracing=os.getenv("LANGSMITH_TRACING", "true").lower() in ("true", "1", "yes"),
            index_cache_dir="",
            max_read_bytes=1_500_000,
        )
        for k, v in overrides.items():
            if v and hasattr(c, k):
                setattr(c, k, v)
        if not c.index_cache_dir and c.repo_path:
            c.index_cache_dir = str(Path(c.repo_path) / ".code_watch")
        return c

    def apply_env(self) -> None:
        if self.openai_api_key:
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
        if self.openai_base_url:
            os.environ["OPENAI_BASE_URL"] = self.openai_base_url
        if self.langsmith_api_key:
            os.environ["LANGSMITH_API_KEY"] = self.langsmith_api_key
        os.environ["LANGSMITH_TRACING"] = str(self.langsmith_tracing).lower()
        os.environ["LANGSMITH_PROJECT"] = self.langsmith_project
