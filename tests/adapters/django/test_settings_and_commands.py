"""The settings bridge, and the operational commands.

The bridge tests exist because a misspelled settings key that is silently ignored
leaves a deployment running the default it was configured to replace — and every
attestation it produces records a value nobody chose.
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from attest.adapters.django.models import PendingAction
from attest.adapters.django.settings import SettingsBridge
from attest.adapters.django.stores import DjangoAuditSink, DjangoRunStore
from attest.kernel.codec import AttestationCodec
from attest.kernel.config import AssuranceTier, ModelTier
from attest.kernel.errors import ConfigurationError

pytestmark = pytest.mark.unit


# ── SettingsBridge ───────────────────────────────────────────────────────────


def test_a_minimal_mapping_produces_a_validated_config() -> None:
    config = SettingsBridge.from_mapping({"BRAND": "acme"})
    assert config.brand == "acme"
    assert config.currency == "USD"


def test_keys_are_mapped_onto_the_frozen_dataclass() -> None:
    config = SettingsBridge.from_mapping(
        {
            "BRAND": "acme",
            "CURRENCY": "GBP",
            "CURRENCY_SYMBOL": "£",
            "LOCALE": "en_GB",
            "MAX_STEPS": 4,
            "DAILY_BUDGET": "500.00",
            "MODELS": {"fast": "m-fast", "reasoning": "m-slow"},
            "ASSURANCE_TIER": "full",
        }
    )
    assert config.currency_symbol == "£"
    assert config.models[ModelTier.FAST] == "m-fast"
    assert config.assurance_tier is AssuranceTier.FULL


def test_an_unknown_key_is_refused_rather_than_ignored() -> None:
    with pytest.raises(ConfigurationError, match="MAX_STEP"):
        SettingsBridge.from_mapping({"BRAND": "acme", "MAX_STEP": 4})


def test_a_missing_brand_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="BRAND"):
        SettingsBridge.from_mapping({"CURRENCY": "GBP"})


def test_an_unknown_model_tier_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="valid tiers"):
        SettingsBridge.from_mapping({"BRAND": "acme", "MODELS": {"turbo": "m"}})


def test_an_unknown_assurance_tier_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="valid tiers"):
        SettingsBridge.from_mapping({"BRAND": "acme", "ASSURANCE_TIER": "paranoid"})


def test_validation_is_the_dataclass_not_the_bridge() -> None:
    """One definition of a valid configuration, so a worker gets identical checks."""
    with pytest.raises(ConfigurationError, match="max_steps"):
        SettingsBridge.from_mapping({"BRAND": "acme", "MAX_STEPS": 999})


def test_config_is_read_from_django_settings() -> None:
    assert SettingsBridge.from_settings().brand == "acme"


def test_an_absent_settings_block_is_refused() -> None:
    class Bare:
        pass

    with pytest.raises(ConfigurationError, match="ATTEST"):
        SettingsBridge.from_settings(Bare())


# ── verify_audit_chain ───────────────────────────────────────────────────────


def persist(made: Any) -> None:
    DjangoAuditSink().append_many(made.events)
    DjangoRunStore().create(made.attestation)


def test_a_sealed_chain_verifies(build: Any, now: datetime) -> None:
    persist(build.sealed(now, run_id="run_ok", count=3))
    out = io.StringIO()
    call_command("verify_audit_chain", "--run-id", "run_ok", stdout=out)
    assert "OK" in out.getvalue()
    assert "sealed" in out.getvalue()


def test_a_gap_is_reported_because_linkage_alone_cannot_see_it(build: Any, now: datetime) -> None:
    """Remove e2 and re-point e3 at e1: every stored hash still agrees. Density does not."""
    made = build.sealed(now, run_id="run_gap", count=3)
    sink = DjangoAuditSink()
    sink.append_many([made.events[0], made.events[2]])
    DjangoRunStore().create(made.attestation)
    with pytest.raises(CommandError, match="1 chain"):
        call_command("verify_audit_chain", "--run-id", "run_gap", stdout=io.StringIO())


def test_a_rewritten_event_is_caught_because_hashes_are_recomputed(
    build: Any, now: datetime
) -> None:
    """The check a stored-linkage walk cannot make.

    The event's own content is changed while its recorded ``previous_hash`` is left
    intact — consistent on paper, and only a recomputed hash shows it.
    """
    made = build.sealed(now, run_id="run_rewritten", count=3)
    forged = replace(made.events[1], payload={"k": "rewritten"})

    # The chain as it would look if event 2 had been rewritten at rest: dense 1..3,
    # every stored previous_hash untouched, and only event 2's content different.
    # A walk over the stored columns finds nothing wrong with this.
    DjangoAuditSink().append_many([made.events[0], forged, made.events[2]])
    DjangoRunStore().create(made.attestation)

    with pytest.raises(CommandError, match="1 chain"):
        call_command("verify_audit_chain", "--run-id", "run_rewritten", stdout=io.StringIO())


def test_an_unsealed_run_is_reported_as_unsealed(build: Any, now: datetime) -> None:
    DjangoAuditSink().append(build.event(now, run_id="run_unsealed"))
    with pytest.raises(CommandError):
        call_command("verify_audit_chain", "--run-id", "run_unsealed", stdout=io.StringIO())


def test_a_run_with_no_events_does_not_pass_silently() -> None:
    with pytest.raises(CommandError):
        call_command("verify_audit_chain", "--run-id", "run_absent", stdout=io.StringIO())


def test_the_command_states_that_event_hashes_are_recomputed(build: Any, now: datetime) -> None:
    """What a verification covers is part of what it is worth, so it is printed."""
    persist(build.sealed(now, run_id="run_ok", count=2))
    out = io.StringIO()
    call_command("verify_audit_chain", stdout=out)
    assert "recomputed from content: True" in out.getvalue()


def test_a_truncated_sweep_says_so(build: Any, now: datetime) -> None:
    persist(build.sealed(now, run_id="run_a", count=1))
    persist(build.sealed(now, run_id="run_b", count=1))
    out = io.StringIO()
    call_command("verify_audit_chain", "--limit", "1", stdout=out)
    assert "Stopped at --limit" in out.getvalue()


# ── expire_pending ───────────────────────────────────────────────────────────


def test_expiry_is_swept_rather_than_merely_recorded(now: datetime) -> None:
    PendingAction.objects.create(
        approval_id="apr_stale",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="c" * 64,
        opened_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    out = io.StringIO()
    call_command("expire_pending", stdout=out)
    assert PendingAction.objects.get(pk="apr_stale").state == PendingAction.EXPIRED
    assert "apr_stale" in out.getvalue()


# ── export_bundle ────────────────────────────────────────────────────────────


def test_a_sealed_final_run_exports_and_the_bundle_decodes(
    build: Any, now: datetime, tmp_path: Path
) -> None:
    made = build.sealed(now, run_id="run_export", count=3)
    persist(made)
    call_command("export_bundle", "run_export", "--out", str(tmp_path), stdout=io.StringIO())

    bundle = tmp_path / "run_export"
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["events"] == 3
    assert manifest["event_hashes_recomputed"] is True
    assert manifest["chain_sealed"] is True

    # The exported attestation is the record, not a summary of it.
    exported = AttestationCodec.decode((bundle / "attestation.json").read_bytes())
    assert exported == made.attestation

    verify = (bundle / "VERIFY.md").read_text()
    assert "does not establish" in verify


def test_the_manifest_hashes_cover_every_file(build: Any, now: datetime, tmp_path: Path) -> None:
    """A manifest that does not cover a file is a file nobody can check."""
    persist(build.sealed(now, run_id="run_export", count=2))
    call_command("export_bundle", "run_export", "--out", str(tmp_path), stdout=io.StringIO())
    bundle = tmp_path / "run_export"
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((bundle / name).read_bytes()).hexdigest() == digest


def test_an_unsealed_run_will_not_export(build: Any, now: datetime, tmp_path: Path) -> None:
    DjangoRunStore().create(build.attestation(now, run_id="run_unsealed_export"))
    with pytest.raises(CommandError, match="not sealed"):
        call_command(
            "export_bundle", "run_unsealed_export", "--out", str(tmp_path), stdout=io.StringIO()
        )


def test_a_run_with_pending_warrants_will_not_export(
    build: Any, now: datetime, tmp_path: Path
) -> None:
    """A bundle is what goes to a regulator; unevaluated warrants must not ship as settled."""
    made = build.sealed(now, run_id="run_pending", count=2)
    pending = replace(
        made.attestation,
        warrants=build.attestation(now, run_id="run_pending", pending=True).warrants,
    )
    DjangoAuditSink().append_many(made.events)
    DjangoRunStore().create(pending)
    with pytest.raises(CommandError, match="pending"):
        call_command("export_bundle", "run_pending", "--out", str(tmp_path), stdout=io.StringIO())


def test_a_run_whose_chain_does_not_verify_will_not_export(
    build: Any, now: datetime, tmp_path: Path
) -> None:
    made = build.sealed(now, run_id="run_broken", count=3)
    DjangoAuditSink().append_many([made.events[0], made.events[2]])
    DjangoRunStore().create(made.attestation)
    with pytest.raises(CommandError, match="does not verify"):
        call_command("export_bundle", "run_broken", "--out", str(tmp_path), stdout=io.StringIO())


def test_an_unknown_run_will_not_export(tmp_path: Path) -> None:
    with pytest.raises(CommandError, match="no attestation"):
        call_command("export_bundle", "run_absent", "--out", str(tmp_path), stdout=io.StringIO())
