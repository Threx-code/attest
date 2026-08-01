"""L1 — capabilities. The warrants, made real.

Evidence verification, completeness, authority and obligations, the execution
boundary, the hash-chained audit, guards, memory, judging, witnessing, and data
lineage all live here.

Two rules this layer is held to, both machine-checked:

*It never imports L2.* A guard cannot know there is an agent loop.

*It never reaches for infrastructure directly.* No database driver, no HTTP client,
no provider SDK. Everything external arrives through a port defined in
:mod:`attest.kernel`, so a capability is testable without a network and a host can
adopt one against tables it already has.

Domain profiles are consumed here and never imported here — this layer depends on the
*protocol*, never on any concrete profile. That is what keeps the world open.
"""

from __future__ import annotations

__all__: list[str] = []
