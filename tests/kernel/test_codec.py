"""The wire format — round-trip fidelity, and the integrity check that guards it.

A codec is only worth having if a decoded record is *the same record*. Equality on the
value objects is the check that matters here, not field-by-field spot checks: a
dataclass comparison catches the field somebody adds next year and forgets to encode,
which is exactly the failure that would otherwise surface as a silently incomplete
audit trail years later.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation, CostRecord, EffectRecord
from attest.kernel.audit import AuditEvent, RunSeal
from attest.kernel.canonical import Canonical, CanonicalisationError
from attest.kernel.codec import AttestationCodec, AuditEventCodec, CodecError
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ModelRef,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectClasses, EffectSemantics, EffectState, IdempotencyMode
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    Persistence,
    SourceRef,
    SourceType,
    ValidityWindow,
)
from attest.kernel.identifiers import (
    ActorId,
    CorpusId,
    EvidenceId,
    GrantId,
    Hash,
    RunId,
    TenantId,
)
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
RUN = RunId("run_codec")


def source() -> SourceRef:
    return SourceRef(
        source_id="doc-1",
        source_type=SourceType.STATUTE,
        authority=AuthorityLevel.AUTHORITATIVE,
        version="2026-04",
        retrieved_at=AT,
        integrity_hash=Hash("b" * 64),
        issuer="HMSO",
        validity=ValidityWindow(effective_from=date(2026, 1, 1), effective_to=date(2027, 1, 1)),
        tenant=TenantId("t1"),
    )


def evidence() -> Evidence:
    """Deliberately awkward: nested derivation, and every scalar type the form tags."""
    leaf = Evidence(
        evidence_id=EvidenceId("ev_leaf"),
        kind=EvidenceKinds.RECORD_VALUE,
        source=source(),
        value={
            "amount": Decimal("500000.00"),
            "as_at": AT,
            "effective": date(2026, 3, 1),
            "ratio": 0.125,
            "raw": b"\x00\x01\x02",
            "count": 3,
            "flag": True,
            "absent": None,
            "labels": ["a", "b"],
        },
        persistence=Persistence.EMBEDDED,
        metadata={"retrieved_by": "retriever-1"},
    )
    return Evidence(
        evidence_id=EvidenceId("ev_root"),
        kind=EvidenceKinds.DERIVATION,
        source=source(),
        value="derived from the ledger",
        sub_evidence=(leaf,),
    )


def context() -> ExecutionContext:
    return ExecutionContext(
        run_id=RUN,
        captured_at=AT,
        identity=IdentitySnapshot(
            actor=ActorId("alice"),
            tenant=TenantId("t1"),
            capabilities=frozenset({"transfer", "read"}),
            roles=frozenset({"analyst"}),
        ),
        binding=TenantBinding(
            tenant=TenantId("t1"),
            profile=ProfileRef(name="generic", version="1.0.0", jurisdiction="UK"),
            config_hash=Hash("c" * 64),
            residency_regions=frozenset({"eu-west-2"}),
        ),
        framework_version="0.1.0",
        policy_version="2026.07",
        evidence=(evidence(),),
        prompt_hashes={"main": Hash("d" * 64)},
        tool_spec_hashes={"transfer": Hash("e" * 64)},
        corpus_epochs={CorpusId("corpus-1"): "epoch-4"},
        model=ModelRef(
            provider="anthropic",
            model_id="claude-opus-5",
            family="claude",
            parameters={"max_tokens": 1024, "top": Decimal("0.9")},
            seed=7,
            failover=True,
            training_attestation=RunId("run_training"),
        ),
        pricing_version="2026-07-01",
        flow_spec_version="flow-3",
        seed=7,
    )


def action() -> Action:
    return Action(
        tool="transfer_funds",
        actor=ActorId("alice"),
        tenant=TenantId("t1"),
        arguments={"amount": Decimal("500000.00"), "to": "acct-9", "when": AT},
        semantics=EffectSemantics(reversible=False, idempotent_upstream=True),
        idempotency=IdempotencyMode.KEYED,
        effects=frozenset({EffectClasses.FINANCIAL, EffectClasses.EXTERNAL}),
        capability="transfer",
        metadata={"channel": "faster-payments"},
    )


def seal() -> RunSeal:
    return RunSeal(
        run_id=RUN,
        event_count=4,
        first_sequence=1,
        last_sequence=4,
        head_hash=Hash("f" * 64),
        attestation_hash=Hash("a" * 64),
        sealed_at=AT + timedelta(seconds=5),
        signer="key-1",
        signature="sig",
    )


def attestation(**overrides: object) -> Attestation:
    fields: dict[str, object] = {
        "run_id": RUN,
        "verdict": Verdict.ALLOW_WITH_WARNINGS,
        "context": context(),
        "created_at": AT,
        "answer": "the transfer is permitted",
        "structured": {"amount": Decimal("500000.00")},
        "warrants": {
            WarrantKinds.EPISTEMIC: WarrantReport(
                kind=WarrantKinds.EPISTEMIC,
                status=WarrantStatus.EVALUATED,
                satisfied=True,
                findings=(
                    Finding(
                        code="source_superseded",
                        message="the cited version was superseded",
                        severity=Severity.WARNING,
                        data={"source": "doc-1"},
                    ),
                ),
                confidence=0.92,
                verifier_ref="exact-v1",
            ),
            WarrantKinds.AUTHORITY: WarrantReport(
                kind=WarrantKinds.AUTHORITY,
                status=WarrantStatus.EVALUATED,
                satisfied=True,
            ),
        },
        "effects": (
            EffectRecord(
                action=action(),
                state=EffectState.COMMITTED,
                grant_id=GrantId("g1"),
                external_reference="fp-777",
                idempotency_key="idem-1",
                submitted_at=AT,
                settled_at=AT + timedelta(seconds=2),
                detail="settled",
            ),
        ),
        "cost": CostRecord(
            input_tokens=1200,
            output_tokens=340,
            cached_tokens=900,
            currency="GBP",
            amount="1.2345",
            pricing_version="2026-07-01",
        ),
        "seal": seal(),
        "supersedes": RunId("run_previous"),
        "metadata": {"channel": "api"},
    }
    fields.update(overrides)
    return Attestation(**fields)  # type: ignore[arg-type]


# ── Round trip ───────────────────────────────────────────────────────────────


def test_a_fully_populated_attestation_round_trips_to_an_equal_object() -> None:
    """Equality on the whole object, so a field added later and never encoded fails."""
    original = attestation()
    restored = AttestationCodec.decode(AttestationCodec.encode(original))
    assert restored == original


def test_the_content_hash_survives_the_round_trip() -> None:
    original = attestation()
    assert AttestationCodec.decode(AttestationCodec.encode(original)).content_hash() == (
        original.content_hash()
    )


def test_encoding_is_deterministic() -> None:
    """Two encodings of the same record are byte-identical, so a store can dedupe on them."""
    assert AttestationCodec.encode(attestation()) == AttestationCodec.encode(attestation())


def test_the_scalar_types_inside_evidence_survive_rather_than_becoming_strings() -> None:
    """A Decimal that comes back a string is a financial record that silently changed."""
    restored = AttestationCodec.decode(AttestationCodec.encode(attestation()))
    leaf = restored.context.evidence[0].sub_evidence[0]
    assert leaf.value["amount"] == Decimal("500000.00")
    assert isinstance(leaf.value["amount"], Decimal)
    assert leaf.value["as_at"] == AT
    assert leaf.value["effective"] == date(2026, 3, 1)
    assert leaf.value["raw"] == b"\x00\x01\x02"
    assert leaf.value["ratio"] == 0.125
    assert leaf.value["flag"] is True
    assert leaf.value["absent"] is None


def test_a_minimal_attestation_round_trips() -> None:
    """The optional half of the record is genuinely optional."""
    minimal = Attestation(run_id=RUN, verdict=Verdict.ALLOW, context=context(), created_at=AT)
    assert AttestationCodec.decode(AttestationCodec.encode(minimal)) == minimal


def test_a_refusal_round_trips_with_its_typed_reason() -> None:
    refused = attestation(
        verdict=Verdict.REFUSE,
        effects=(),
        refusal=Refusal(
            reason=RefusalReason("residency_unavailable"),
            detail="no provider in region",
            warrant=WarrantKinds.BOUNDARY,
            subject_message="We cannot process this right now.",
            metadata={"region": "eu-west-2"},
        ),
    )
    restored = AttestationCodec.decode(AttestationCodec.encode(refused))
    assert restored == refused
    assert restored.refusal is not None
    assert restored.refusal.warrant == WarrantKinds.BOUNDARY


def test_a_pending_warrant_round_trips_and_stays_non_final() -> None:
    """Deferred assurance must survive storage, or a non-final record exports as settled."""
    deferred = attestation(
        warrants={
            WarrantKinds.EPISTEMIC: WarrantReport(
                kind=WarrantKinds.EPISTEMIC,
                status=WarrantStatus.PENDING,
                satisfied=False,
            )
        }
    )
    restored = AttestationCodec.decode(AttestationCodec.encode(deferred))
    assert restored.is_final is False
    assert restored.pending_warrants == frozenset({WarrantKinds.EPISTEMIC})


def test_an_open_warrant_kind_from_a_domain_survives() -> None:
    """The vocabulary is open; a codec that only knew the six core kinds would close it."""
    from attest.kernel.warrants import WarrantKind

    calibration = WarrantKind("calibration")
    domain = attestation(
        warrants={
            calibration: WarrantReport(
                kind=calibration, status=WarrantStatus.EVALUATED, satisfied=True
            )
        }
    )
    assert AttestationCodec.decode(AttestationCodec.encode(domain)).warrant(calibration).satisfied


# ── Integrity ────────────────────────────────────────────────────────────────


def test_a_tampered_payload_is_refused_on_decode() -> None:
    """The whole reason the codec verifies rather than merely parses."""
    payload = AttestationCodec.encode(attestation())
    tampered = payload.replace(b"the transfer is permitted", b"the transfer is forbidden")
    assert tampered != payload
    with pytest.raises(CodecError, match="content hash"):
        AttestationCodec.decode(tampered)


def test_a_payload_from_an_unreadable_future_version_is_refused() -> None:
    """A major release owes a shim; refusing is where its absence shows up."""
    form = AttestationCodec.to_form(attestation())
    form["version"] = 99
    with pytest.raises(CodecError, match="cannot be read"):
        AttestationCodec.from_form(form)


def test_a_payload_of_another_format_is_refused() -> None:
    form = AttestationCodec.to_form(attestation())
    form["format"] = "something.else"
    with pytest.raises(CodecError, match="format"):
        AttestationCodec.from_form(form)


def test_bytes_that_are_not_json_are_refused() -> None:
    with pytest.raises(CodecError, match="not canonical JSON"):
        AttestationCodec.decode(b"\xff\xfe not json")


def test_a_value_using_a_reserved_tag_is_refused_at_write_time() -> None:
    """Failing at write is recoverable; a value that changes type at read is not."""
    trap = attestation(metadata={"payload": {"__decimal__": "1.0"}})
    with pytest.raises((CodecError, CanonicalisationError), match="__decimal__"):
        AttestationCodec.encode(trap)


def test_the_reserved_tag_check_reaches_inside_lists() -> None:
    trap = attestation(metadata={"items": [{"ok": 1}, {"__date__": "2026-01-01"}]})
    with pytest.raises((CodecError, CanonicalisationError), match="__date__"):
        AttestationCodec.encode(trap)


def test_the_canonicaliser_itself_refuses_a_tag_impersonation() -> None:
    """The codec is not the only caller, and it is not the one that matters most.

    ``Action.action_hash`` calls ``Canonical.digest`` directly. A check that lived
    only at encode time would let a grant issued for one action authorise another —
    the exact binding an action hash exists to make.
    """
    with pytest.raises(CanonicalisationError, match="reserved"):
        Canonical.digest({"amount": {"__decimal__": "12400"}})


def test_a_decimal_and_a_mapping_that_mimics_it_cannot_share_an_action_hash() -> None:
    from attest.kernel.actions import Action

    def act(arguments: dict[str, object]) -> Action:
        return Action(
            tool="transfer",
            actor=ActorId("alice"),
            tenant=TenantId("t1"),
            arguments=arguments,
            semantics=EffectSemantics(),
        )

    real = act({"amount": Decimal("12400")}).action_hash()
    with pytest.raises(CanonicalisationError):
        act({"amount": {"__decimal__": "12400"}}).action_hash()
    assert real


def test_a_set_does_not_collide_with_a_list_of_its_encoded_elements() -> None:
    """Untagged, ``{"a"}`` and ``[\'"a"\']`` encode to identical bytes."""
    assert Canonical.digest({"a", "b"}) != Canonical.digest(['"a"', '"b"'])
    assert Canonical.revive(Canonical.form({"a", "b"})) == {"a", "b"}


# ── Audit events ─────────────────────────────────────────────────────────────


def event(**overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "run_id": RUN,
        "event_type": "effect.committed",
        "occurred_at": AT,
        "payload": {"amount": Decimal("500000.00"), "reference": "fp-777"},
        "parent_event_id": "evt_1",
        "branch": "main",
        "sequence": 3,
        "previous_hash": Hash("a" * 64),
    }
    fields.update(overrides)
    return AuditEvent(**fields)  # type: ignore[arg-type]


def test_an_audit_event_round_trips() -> None:
    assert AuditEventCodec.decode(AuditEventCodec.encode(event())) == event()


def test_an_unsealed_event_round_trips_without_acquiring_a_sequence() -> None:
    """Events arrive unsealed; a codec that defaulted the sequence would fake ordering."""
    unsealed = event(sequence=None, previous_hash=None)
    restored = AuditEventCodec.decode(AuditEventCodec.encode(unsealed))
    assert restored.sequence is None
    assert restored.previous_hash is None


def test_the_event_hash_survives_the_round_trip() -> None:
    """What makes recomputed chain verification possible at all."""
    original = event()
    assert AuditEventCodec.decode(AuditEventCodec.encode(original)).event_hash() == (
        original.event_hash()
    )


def test_a_seal_round_trips() -> None:
    restored = AttestationCodec.decode(AttestationCodec.encode(attestation()))
    assert restored.seal == seal()


def test_an_audit_event_of_another_format_is_refused() -> None:
    form = AuditEventCodec.to_form(event())
    form["format"] = "something.else"
    with pytest.raises(CodecError, match="format"):
        AuditEventCodec.from_form(form)


def test_an_audit_event_from_an_unreadable_version_is_refused() -> None:
    form = AuditEventCodec.to_form(event())
    form["version"] = 99
    with pytest.raises(CodecError, match="cannot be read"):
        AuditEventCodec.from_form(form)


def test_audit_event_bytes_that_are_not_json_are_refused() -> None:
    with pytest.raises(CodecError, match="not canonical JSON"):
        AuditEventCodec.decode(b"{oops")


# ── The revive primitive ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        Decimal("1.25"),
        AT,
        date(2026, 1, 1),
        0.1,
        b"bytes",
        "plain",
        42,
        True,
        None,
        {"nested": {"deep": Decimal("2")}},
        [Decimal("1"), AT],
    ],
)
def test_revive_inverts_form_for_every_tagged_scalar(value: object) -> None:
    assert Canonical.revive(Canonical.form(value)) == value


# ── An untrusted payload cannot escape CodecError ────────────────────────────


@pytest.mark.security
def test_a_deeply_nested_payload_is_refused_before_it_is_parsed() -> None:
    """ATT-15. 60,000 nested objects raised RecursionError straight out of json.loads.

    That is not a CodecError, so StoredChainCheck — which catches CodecError to report
    ALTERED_EVENT — did not catch it, and the verification sweep crashed instead of
    reporting tampering. Anyone able to INSERT an audit row (the append-only trigger
    permits inserts) could stop the sweep rather than be caught by it.
    """
    bomb = b'{"a":' * 60_000 + b"1" + b"}" * 60_000
    with pytest.raises(CodecError, match="nests"):
        AuditEventCodec.decode(bomb)
    with pytest.raises(CodecError, match="nests"):
        AttestationCodec.decode(bomb)


@pytest.mark.security
def test_an_oversized_payload_is_refused_before_it_is_parsed() -> None:
    """Checking after json.loads has already paid for the parse."""
    with pytest.raises(CodecError, match="above the"):
        AuditEventCodec.decode(b'{"a":"' + b"x" * (9 * 1024 * 1024) + b'"}')


@pytest.mark.security
def test_a_payload_field_of_the_wrong_type_is_a_codec_error() -> None:
    """A list here used to raise AttributeError out of .items()."""
    import json

    form = {
        "format": "attest.audit_event",
        "version": 1,
        "run_id": "run_1",
        "event_type": "run.dispatched",
        "occurred_at": "2026-07-31T12:00:00+00:00",
        "payload": ["not", "a", "mapping"],
    }
    with pytest.raises(CodecError):
        AuditEventCodec.decode(json.dumps(form).encode())


@pytest.mark.security
def test_a_payload_that_is_not_an_object_is_a_codec_error() -> None:
    with pytest.raises(CodecError, match="not an object"):
        AuditEventCodec.decode(b"[1, 2, 3]")


def test_a_brace_inside_a_string_does_not_count_toward_nesting() -> None:
    """Otherwise a legitimate record quoting JSON would be refused."""
    from attest.kernel.codec import _Limits

    assert _Limits.nesting(b'{"note": "{{{{{{{{{{"}') == 1
