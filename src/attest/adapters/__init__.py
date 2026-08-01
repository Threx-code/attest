"""L4 — adapters. Optional integrations.

Reference implementations of the kernel's ports: in-memory and SQLite stores, the
Django models and migrations, queue wrappers, provider clients.

**Offered, never required.** A host with existing tables implements the ports against
them and uses none of this. That is what makes adoption incremental for codebases
whose own tables have already diverged — and it is why nothing in the core imports
anything here.
"""

from __future__ import annotations

__all__: list[str] = []
