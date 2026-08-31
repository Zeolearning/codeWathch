from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from code_watch.config import CodeWatchConfig


@dataclass
class RepoContext:
    repo_root: Path
    config: CodeWatchConfig = field(default_factory=CodeWatchConfig)
    git_root: Optional[Path] = None

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()
        if not self.repo_root.is_dir():
            raise NotADirectoryError(f"repo_root is not a directory: {self.repo_root}")
        git_dir = self._find_git_root(self.repo_root)
        self.git_root = git_dir if git_dir else self.repo_root

    @staticmethod
    def _find_git_root(path: Path) -> Optional[Path]:
        for p in [path] + list(path.parents):
            if (p / ".git").is_dir():
                return p
        return None

    def resolve_path(self, *parts: str) -> Path:
        raw = Path(*parts)
        if raw.is_absolute():
            # resolve() normalizes ".." segments; without it an absolute path
            # like /root/vul/../../etc/passwd passes the lexical relative_to
            # check in ensure_inside while reading outside the root on disk.
            return raw.resolve()
        return (self.repo_root / raw).resolve()

    def ensure_inside(self, resolved: Path) -> Path:
        try:
            resolved.relative_to(self.repo_root)
        except ValueError:
            raise PermissionError(f"path escapes repo root: {resolved}")
        return resolved

    def in_repo_path(self, *parts: str) -> Path:
        return self.ensure_inside(self.resolve_path(*parts))
