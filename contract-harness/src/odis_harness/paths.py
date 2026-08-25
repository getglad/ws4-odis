"""Filesystem anchors for the harness's own data files.

Deliberately dependency-free and imported by both `bundle` and `contracts`, so
neither package has to reach into the other to find a directory.
"""

from __future__ import annotations

from pathlib import Path

#: A schemas directory is only accepted if it holds this file. Without the check, any
#: unrelated `schemas/` directory in the working directory captures resolution and the
#: harness fails to load its own bundle.
SCHEMAS_MARKER = "odis.bundle.v1.json"


def repo_root() -> Path:
    """The harness root, anchored to this file rather than the working directory."""
    # paths.py -> odis_harness -> src -> <repo root>
    return Path(__file__).resolve().parents[2]


def default_schemas_dir() -> Path:
    """`$CWD/schemas` when it holds the harness schemas, else the source-tree copy.

    The working-directory candidate comes first so a deployment can override the
    shipped schemas, but it has to actually contain `SCHEMAS_MARKER` to win. Returns
    the source-tree path when neither qualifies, so the caller fails on a clear
    missing-file error rather than on `None`.
    """
    candidates = [Path.cwd() / "schemas", repo_root() / "schemas"]
    for candidate in candidates:
        if (candidate / SCHEMAS_MARKER).is_file():
            return candidate
    return candidates[-1]


__all__ = ["SCHEMAS_MARKER", "default_schemas_dir", "repo_root"]
