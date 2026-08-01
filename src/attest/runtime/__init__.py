"""L2 — runtime. Putting the capabilities together.

Declarative agent specs, the Flow graph and the topologies expressible in it, intent
routing, two-phase streaming, delegation and handoff, and the three replay modes.

Nothing here may be reached from L1. If a capability needs something this layer knows,
the design is wrong: the dependency points the other way.
"""

from __future__ import annotations

__all__: list[str] = []
