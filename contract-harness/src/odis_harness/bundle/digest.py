"""`policy_digest` — sha256 over the canonical-serialized bundle.

The digest covers the *entire* loaded bundle (metadata + policy + routing + governed
tools + per-family `default_mode`), so policy and routing are bound together: a policy
re-pointed at a different vendor produces a different digest.

It *detects*, it does not prevent. Nothing compares it to a reference value — it is
stamped on every envelope so an auditor can reconcile a decision against the exact grant
that authorized it. Prevention is the signature over the whole payload, and only the
Vault path verifies that for real; `serve`/`demo` inject `FixtureSignatureVerifier`,
which accepts anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from odis_harness.bundle.types import Bundle


def policy_digest(bundle: Bundle) -> str:
    """Return the sha256 hex digest of the bundle's canonical serialization.

    Canonicalization: `json.dumps(asdict(bundle), sort_keys=True)` — UTF-8
    encoded. `sort_keys=True` ensures dict insertion order does not affect the
    digest.
    """
    canonical = json.dumps(asdict(bundle), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = ["policy_digest"]
