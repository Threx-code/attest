"""Django adapter — **offered, never required**.

.. code-block:: text

    attest.adapters.django
      ├── settings.py       SettingsBridge: settings.ATTEST -> AttestConfig
      ├── models.py         AttestationRecord · AuditEventRecord · PendingAction
      │                     AutonomyPolicy · MemoryRecord · nonce/budget rows
      ├── migrations/       including the append-only and immutability triggers
      ├── stores.py         RunStore · AuditSink · NonceStore · BudgetStore
      │                     ApprovalStore · MemoryStore
      ├── serializers.py    DRF, and structurally unable to drop warnings
      ├── views.py          read the record, work the approval queue
      ├── operations.py     kill switch · approval queue · chain · queue health
      └── management/       verify_audit_chain · expire_pending · export_bundle

Adding this to ``INSTALLED_APPS`` is one way to satisfy the kernel's ports. It is not
the way. A host whose ``AgentRun`` table already exists writes classes satisfying the
same protocols against its own schema, runs no migration, and adopts the gateway today
and the rest later — or never.

**Nothing here is imported by the core.** The ``import-linter`` contract in CI forbids
``django`` anywhere below L4, so the dependency cannot creep inward unnoticed.

Only :class:`~attest.adapters.django.settings.SettingsBridge` is re-exported at package
level. Everything else lives in a submodule because importing a Django model before the
app registry is ready raises, and a package ``__init__`` that did so would make the
import order a trap.

Adding ``"attest.adapters.django"`` to ``INSTALLED_APPS`` is enough — Django finds
:class:`~attest.adapters.django.apps.AttestAppConfig` in ``apps.py`` on its own, and
that config sets the app label to ``attest`` rather than letting it default to
``django``.
"""

from __future__ import annotations

from attest.adapters.django.settings import SettingsBridge

__all__ = ["SettingsBridge"]
