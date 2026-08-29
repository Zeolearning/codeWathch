from __future__ import annotations

import os
from typing import Optional

from langsmith import Client as LangSmithClient

_client: Optional[LangSmithClient] = None


def get_client() -> Optional[LangSmithClient]:
    global _client
    if _client is None and os.getenv("LANGSMITH_API_KEY"):
        try:
            _client = LangSmithClient()
        except Exception:
            _client = None
    return _client


def get_run_url_for_name(project_name: str, run_name: str) -> Optional[str]:
    """Return the LangSmith URL for the most recent run with the given run_name.

    Uses only public Client API (list_runs + get_run_url). Returns None when the
    client is unavailable or no matching run is found.
    """
    client = get_client()
    if client is None:
        return None
    try:
        run = next(
            client.list_runs(
                project_name=project_name,
                filter=f'eq(name, "{run_name}")',
                limit=1,
            )
        )
        return client.get_run_url(run=run, project_name=project_name)
    except StopIteration:
        return None
    except Exception:
        return None
