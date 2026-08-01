"""The attestation wire format — the thing that makes a record outlive this package.

Without a codec, "durable audit trail" is a promise the framework cannot keep. A store
that holds opaque bytes it cannot read back is a filing cabinet with no key: the record
survives, and nothing can check it, replay it, or verify a chain against it.

.. rubric:: Two properties that make this safe to depend on

**Decoding verifies the content hash.** :meth:`AttestationCodec.decode` recomputes
:meth:`Attestation.content_hash` over the object it just built and compares it to the
hash recorded in the envelope. A payload edited in the database, a codec that drifted
from the value objects, a field silently dropped by a refactor — all three surface as a
raised :class:`~attest.kernel.errors.IntegrityError` at read time rather than as a
plausible-looking record that quietly says something else. This is why the codec lives
in the kernel beside :class:`~attest.kernel.canonical.Canonical` rather than in an
adapter.

**Scalars round-trip through the hashing layer itself.** ``Canonical.form`` already
tags the types JSON cannot express — ``__decimal__``, ``__datetime__``, ``__bytes__``
— so :meth:`Canonical.revive` inverts exactly that tagging. A parallel decoder would be
a second definition of the format, and the one nobody looks at would rot.

.. rubric:: What the tagging cannot express, and what is done about it

A mapping in user data whose *only* key is one of those five sentinels is
indistinguishable from a tagged scalar. Rather than let it come back as a different
type, encoding **refuses** it. Failing at write is recoverable; a value that silently
changes type between write and read is not. See :attr:`Canonical.RESERVED_TAGS`.

.. rubric:: Versioning

The envelope carries ``format`` and ``version``. A reader that meets a version it does
not know refuses rather than guessing — and because major versions of this package must
verify prior-major attestations for the retention period, that refusal is the signal
that a shim is owed, not an error to work around.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation, CostRecord, EffectRecord
from attest.kernel.audit import AuditEvent, RunSeal
from attest.kernel.canonical import Canonical
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ModelRef,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectClass, EffectSemantics, EffectState, IdempotencyMode
from attest.kernel.errors import IntegrityError
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKind,
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
from attest.kernel.warrants import Finding, Severity, WarrantKind, WarrantReport, WarrantStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["AttestationCodec", "AuditEventCodec", "CodecError"]


class _Limits:
    """Bounds applied before parsing, not after.

    A payload is untrusted input from the moment it is read: it may have been written
    by an earlier version, edited in the database, or supplied in a bundle. Checking
    the size after ``json.loads`` has already paid for the parse, and checking the
    nesting after means the recursion has already happened.
    """

    MAX_BYTES: Final = 8 * 1024 * 1024
    """Generous for a real attestation with embedded evidence, and finite."""

    MAX_NESTING: Final = 200
    """Well above any legitimate record — the evidence tree is capped at depth 32 —
    and far below the recursion limit ``json.loads`` will hit."""

    @classmethod
    def assert_within(cls, payload: bytes, *, what: str) -> None:
        if len(payload) > cls.MAX_BYTES:
            raise CodecError(
                f"{what} payload is {len(payload)} bytes, above the {cls.MAX_BYTES} "
                f"ceiling. Refusing before parsing: a stored record is untrusted input."
            )
        depth = cls.nesting(payload)
        if depth > cls.MAX_NESTING:
            raise CodecError(
                f"{what} payload nests {depth} deep, above the {cls.MAX_NESTING} "
                f"ceiling. Parsing it would raise RecursionError out of json.loads, "
                f"which is not a CodecError and would crash a verification sweep "
                f"rather than reporting the record as altered."
            )

    @staticmethod
    def nesting(payload: bytes) -> int:
        """Maximum bracket depth, counted without parsing.

        Strings are skipped so a brace inside a quoted value does not count, which is
        the only subtlety — and it is cheaper than the parse it is protecting.
        """
        depth = maximum = 0
        in_string = escaped = False
        for byte in payload:
            character = chr(byte)
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character in "{[":
                depth += 1
                maximum = max(maximum, depth)
            elif character in "}]":
                depth -= 1
        return maximum


class CodecError(IntegrityError):
    """A record could not be encoded or decoded faithfully.

    An :class:`~attest.kernel.errors.IntegrityError` rather than a plain failure: every
    way of reaching this means the stored record and the object it claims to describe
    have come apart.
    """


class _Values:
    """Round-tripping for the ``Any``-typed leaves.

    Evidence values, tool arguments, model parameters and metadata are open by design
    — a domain puts what it needs there. They go through the canonical form so the
    encoding is the same one the hash is taken over, and come back through
    :meth:`Canonical.revive`.
    """

    @staticmethod
    def dump(value: Any, *, where: str) -> Any:
        _Values.assert_no_reserved_tag(value, where=where)
        return Canonical.form(value)

    @staticmethod
    def load(form: Any) -> Any:
        return Canonical.revive(form)

    @staticmethod
    def dump_mapping(mapping: Mapping[str, Any], *, where: str) -> dict[str, Any]:
        return {key: _Values.dump(item, where=f"{where}[{key!r}]") for key, item in mapping.items()}

    @staticmethod
    def load_mapping(form: Mapping[str, Any]) -> dict[str, Any]:
        return {key: _Values.load(item) for key, item in form.items()}

    @staticmethod
    def assert_no_reserved_tag(value: Any, *, where: str) -> None:
        """Refuse a mapping that would come back as a scalar.

        Checked at write time on purpose. A value that changes type between write and
        read corrupts a record nobody will think to re-examine; a refusal here is a
        bug report with a location in it.
        """
        if isinstance(value, dict):
            if len(value) == 1 and next(iter(value)) in Canonical.RESERVED_TAGS:
                tag = next(iter(value))
                raise CodecError(
                    f"{where} is a mapping whose only key is {tag!r}, which the "
                    f"canonical form reserves for tagged scalars. Encoded as-is it "
                    f"would decode as a {tag.strip('_')} rather than a mapping. Nest "
                    f"it under another key, or add a sibling key."
                )
            for key, item in value.items():
                _Values.assert_no_reserved_tag(item, where=f"{where}[{key!r}]")
        elif isinstance(value, list | tuple):
            for index, item in enumerate(value):
                _Values.assert_no_reserved_tag(item, where=f"{where}[{index}]")


class _Times:
    """Timestamps, as canonical strings."""

    @staticmethod
    def dump(moment: datetime | None) -> str | None:
        return None if moment is None else Canonical.form(moment)["__datetime__"]

    @staticmethod
    def load(raw: str | None) -> datetime | None:
        return None if raw is None else datetime.fromisoformat(raw)

    @staticmethod
    def require(raw: str | None, *, field: str) -> datetime:
        moment = _Times.load(raw)
        if moment is None:
            raise CodecError(f"{field} is required and was absent from the payload")
        return moment

    @staticmethod
    def dump_date(day: date | None) -> str | None:
        return None if day is None else day.isoformat()

    @staticmethod
    def load_date(raw: str | None) -> date | None:
        return None if raw is None else date.fromisoformat(raw)


class _Evidence:
    """Evidence, including its recursive derivation chain."""

    @staticmethod
    def dump(item: Evidence) -> dict[str, Any]:
        return {
            "evidence_id": str(item.evidence_id),
            "kind": str(item.kind),
            "source": _Evidence.dump_source(item.source),
            "value": _Values.dump(item.value, where=f"evidence[{item.evidence_id!r}].value"),
            "persistence": item.persistence.value,
            "sub_evidence": [_Evidence.dump(child) for child in item.sub_evidence],
            "metadata": _Values.dump_mapping(
                item.metadata, where=f"evidence[{item.evidence_id!r}].metadata"
            ),
        }

    @staticmethod
    def load(form: Mapping[str, Any]) -> Evidence:
        return Evidence(
            evidence_id=EvidenceId(form["evidence_id"]),
            kind=EvidenceKind(form["kind"]),
            source=_Evidence.load_source(form["source"]),
            value=_Values.load(form["value"]),
            persistence=Persistence(form["persistence"]),
            sub_evidence=tuple(_Evidence.load(child) for child in form.get("sub_evidence", ())),
            metadata=_Values.load_mapping(form.get("metadata", {})),
        )

    @staticmethod
    def dump_source(source: SourceRef) -> dict[str, Any]:
        return {
            "source_id": source.source_id,
            "source_type": source.source_type.value,
            "authority": source.authority.value,
            "version": source.version,
            "retrieved_at": _Times.dump(source.retrieved_at),
            "integrity_hash": str(source.integrity_hash),
            "issuer": source.issuer,
            "validity": {
                "effective_from": _Times.dump_date(source.validity.effective_from),
                "effective_to": _Times.dump_date(source.validity.effective_to),
            },
            "tenant": None if source.tenant is None else str(source.tenant),
        }

    @staticmethod
    def load_source(form: Mapping[str, Any]) -> SourceRef:
        validity = form.get("validity") or {}
        tenant = form.get("tenant")
        return SourceRef(
            source_id=form["source_id"],
            source_type=SourceType(form["source_type"]),
            authority=AuthorityLevel(form["authority"]),
            version=form["version"],
            retrieved_at=_Times.require(form["retrieved_at"], field="source.retrieved_at"),
            integrity_hash=Hash(form["integrity_hash"]),
            issuer=form.get("issuer"),
            validity=ValidityWindow(
                effective_from=_Times.load_date(validity.get("effective_from")),
                effective_to=_Times.load_date(validity.get("effective_to")),
            ),
            tenant=None if tenant is None else TenantId(tenant),
        )


class _Context:
    """The execution context — hashed as one unit, so decoded as one unit."""

    @staticmethod
    def dump(context: ExecutionContext) -> dict[str, Any]:
        return {
            "run_id": str(context.run_id),
            "captured_at": _Times.dump(context.captured_at),
            "identity": {
                "actor": str(context.identity.actor),
                "tenant": str(context.identity.tenant),
                "capabilities": sorted(context.identity.capabilities),
                "roles": sorted(context.identity.roles),
            },
            "binding": {
                "tenant": str(context.binding.tenant),
                "profile": {
                    "name": context.binding.profile.name,
                    "version": context.binding.profile.version,
                    "jurisdiction": context.binding.profile.jurisdiction,
                },
                "config_hash": str(context.binding.config_hash),
                "residency_regions": sorted(context.binding.residency_regions),
            },
            "framework_version": context.framework_version,
            "policy_version": context.policy_version,
            "evidence": [_Evidence.dump(item) for item in context.evidence],
            "prompt_hashes": {key: str(value) for key, value in context.prompt_hashes.items()},
            "tool_spec_hashes": {
                key: str(value) for key, value in context.tool_spec_hashes.items()
            },
            "corpus_epochs": {str(key): value for key, value in context.corpus_epochs.items()},
            "model": None if context.model is None else _Context.dump_model(context.model),
            "pricing_version": context.pricing_version,
            "flow_spec_version": context.flow_spec_version,
            "seed": context.seed,
        }

    @staticmethod
    def load(form: Mapping[str, Any]) -> ExecutionContext:
        identity = form["identity"]
        binding = form["binding"]
        profile = binding["profile"]
        model = form.get("model")
        return ExecutionContext(
            run_id=RunId(form["run_id"]),
            captured_at=_Times.require(form["captured_at"], field="context.captured_at"),
            identity=IdentitySnapshot(
                actor=ActorId(identity["actor"]),
                tenant=TenantId(identity["tenant"]),
                capabilities=frozenset(identity.get("capabilities", ())),
                roles=frozenset(identity.get("roles", ())),
            ),
            binding=TenantBinding(
                tenant=TenantId(binding["tenant"]),
                profile=ProfileRef(
                    name=profile["name"],
                    version=profile["version"],
                    jurisdiction=profile.get("jurisdiction"),
                ),
                config_hash=Hash(binding["config_hash"]),
                residency_regions=frozenset(binding.get("residency_regions", ())),
            ),
            framework_version=form["framework_version"],
            policy_version=form["policy_version"],
            evidence=tuple(_Evidence.load(item) for item in form.get("evidence", ())),
            prompt_hashes={
                key: Hash(value) for key, value in form.get("prompt_hashes", {}).items()
            },
            tool_spec_hashes={
                key: Hash(value) for key, value in form.get("tool_spec_hashes", {}).items()
            },
            corpus_epochs={
                CorpusId(key): value for key, value in form.get("corpus_epochs", {}).items()
            },
            model=None if model is None else _Context.load_model(model),
            pricing_version=form.get("pricing_version"),
            flow_spec_version=form.get("flow_spec_version"),
            seed=form.get("seed"),
        )

    @staticmethod
    def dump_model(model: ModelRef) -> dict[str, Any]:
        return {
            "provider": model.provider,
            "model_id": model.model_id,
            "family": model.family,
            "parameters": _Values.dump_mapping(model.parameters, where="model.parameters"),
            "seed": model.seed,
            "failover": model.failover,
            "training_attestation": (
                None if model.training_attestation is None else str(model.training_attestation)
            ),
        }

    @staticmethod
    def load_model(form: Mapping[str, Any]) -> ModelRef:
        training = form.get("training_attestation")
        return ModelRef(
            provider=form["provider"],
            model_id=form["model_id"],
            family=form.get("family", ""),
            parameters=_Values.load_mapping(form.get("parameters", {})),
            seed=form.get("seed"),
            failover=form.get("failover", False),
            training_attestation=None if training is None else RunId(training),
        )


class _Effects:
    """Effect records, and the actions they concern."""

    @staticmethod
    def dump(record: EffectRecord) -> dict[str, Any]:
        return {
            "action": _Effects.dump_action(record.action),
            "state": record.state.value,
            "grant_id": None if record.grant_id is None else str(record.grant_id),
            "external_reference": record.external_reference,
            "idempotency_key": record.idempotency_key,
            "submitted_at": _Times.dump(record.submitted_at),
            "settled_at": _Times.dump(record.settled_at),
            "detail": record.detail,
        }

    @staticmethod
    def load(form: Mapping[str, Any]) -> EffectRecord:
        grant = form.get("grant_id")
        return EffectRecord(
            action=_Effects.load_action(form["action"]),
            state=EffectState(form["state"]),
            grant_id=None if grant is None else GrantId(grant),
            external_reference=form.get("external_reference"),
            idempotency_key=form.get("idempotency_key"),
            submitted_at=_Times.load(form.get("submitted_at")),
            settled_at=_Times.load(form.get("settled_at")),
            detail=form.get("detail", ""),
        )

    @staticmethod
    def dump_action(action: Action) -> dict[str, Any]:
        return {
            "tool": action.tool,
            "actor": str(action.actor),
            "tenant": str(action.tenant),
            "arguments": _Values.dump_mapping(
                action.arguments, where=f"action[{action.tool!r}].arguments"
            ),
            "semantics": {
                "reversible": action.semantics.reversible,
                "compensatable": action.semantics.compensatable,
                "externally_visible": action.semantics.externally_visible,
                "financially_material": action.semantics.financially_material,
                "legally_binding": action.semantics.legally_binding,
                "idempotent_upstream": action.semantics.idempotent_upstream,
                "transactional": action.semantics.transactional,
            },
            "idempotency": action.idempotency.value,
            "effects": sorted(str(effect) for effect in action.effects),
            "capability": action.capability,
            "metadata": _Values.dump_mapping(
                action.metadata, where=f"action[{action.tool!r}].metadata"
            ),
        }

    @staticmethod
    def load_action(form: Mapping[str, Any]) -> Action:
        return Action(
            tool=form["tool"],
            actor=ActorId(form["actor"]),
            tenant=TenantId(form["tenant"]),
            arguments=_Values.load_mapping(form["arguments"]),
            semantics=EffectSemantics(**form["semantics"]),
            idempotency=IdempotencyMode(form["idempotency"]),
            effects=frozenset(EffectClass(item) for item in form.get("effects", ())),
            capability=form.get("capability"),
            metadata=_Values.load_mapping(form.get("metadata", {})),
        )


class _Warrants:
    """Warrant reports. The mapping is what keeps the framework open, so it is
    encoded as a mapping rather than as four named fields."""

    @staticmethod
    def dump(reports: Mapping[WarrantKind, WarrantReport]) -> dict[str, Any]:
        return {
            str(kind): {
                "kind": str(report.kind),
                "status": report.status.value,
                "satisfied": report.satisfied,
                "confidence": report.confidence,
                "verifier_ref": report.verifier_ref,
                "findings": [
                    {
                        "code": finding.code,
                        "message": finding.message,
                        "severity": finding.severity.value,
                        "data": dict(finding.data),
                    }
                    for finding in report.findings
                ],
            }
            for kind, report in reports.items()
        }

    @staticmethod
    def load(form: Mapping[str, Any]) -> dict[WarrantKind, WarrantReport]:
        return {
            WarrantKind(kind): WarrantReport(
                kind=WarrantKind(report["kind"]),
                status=WarrantStatus(report["status"]),
                satisfied=report["satisfied"],
                findings=tuple(
                    Finding(
                        code=finding["code"],
                        message=finding["message"],
                        severity=Severity(finding["severity"]),
                        data=dict(finding.get("data", {})),
                    )
                    for finding in report.get("findings", ())
                ),
                confidence=report.get("confidence"),
                verifier_ref=report.get("verifier_ref"),
            )
            for kind, report in form.items()
        }


class _Codec:
    """What both codecs do identically: bound the input, then parse it."""

    @classmethod
    def parse(cls, payload: bytes, *, what: str) -> Mapping[str, Any]:
        """Bounded, and always a mapping. Never a partially-decoded record."""
        _Limits.assert_within(payload, what=what)
        try:
            form = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise CodecError(f"{what} payload is not canonical JSON: {exc}") from exc
        if not isinstance(form, dict):
            raise CodecError(
                f"{what} payload decoded to {type(form).__name__}, not an object. A "
                f"record that is not a mapping cannot be a record."
            )
        return form


class AttestationCodec(_Codec):
    """Encodes an :class:`Attestation` to canonical bytes, and reads it back.

    Stateless; the methods are classmethods so a store can use it without holding one.
    """

    FORMAT: ClassVar[str] = "attest.attestation"
    VERSION: ClassVar[int] = 2
    """Bumped when the content hash changed to cover the whole ``SourceRef``.

    Version 1 payloads no longer verify, because the hash they carry was taken over a
    narrower projection. That is the correct outcome and it is why the version exists:
    silently accepting them would mean accepting records whose evidence authority and
    validity window were never covered.
    """

    #: Versions this build can read. Widened, never narrowed — a major release that
    #: dropped one would invalidate every attestation written under it. Version 1 is
    #: absent because nothing has been published under it; a released version would
    #: instead need a shim that re-verifies against the old projection.
    READABLE: ClassVar[frozenset[int]] = frozenset({2})

    @classmethod
    def encode(cls, attestation: Attestation) -> bytes:
        """Canonical bytes for ``attestation``, with its content hash in the envelope.

        ``encode_form`` rather than ``encode``: :meth:`to_form` has already produced a
        canonical form, and a second pass through ``Canonical.form`` would tag the
        tags — a ``{"__decimal__": ...}`` this codec emitted on purpose would come
        back as a mapping rather than a Decimal.
        """
        return Canonical.encode_form(cls.to_form(attestation))

    @classmethod
    def to_form(cls, attestation: Attestation) -> dict[str, Any]:
        refusal = attestation.refusal
        seal = attestation.seal
        return {
            "format": cls.FORMAT,
            "version": cls.VERSION,
            # Recorded so a reader can detect drift without trusting the reader.
            "content_hash": str(attestation.content_hash()),
            "run_id": str(attestation.run_id),
            "verdict": attestation.verdict.value,
            "context": _Context.dump(attestation.context),
            "created_at": _Times.dump(attestation.created_at),
            "answer": attestation.answer,
            "structured": (
                None
                if attestation.structured is None
                else _Values.dump_mapping(attestation.structured, where="structured")
            ),
            "warrants": _Warrants.dump(attestation.warrants),
            "effects": [_Effects.dump(record) for record in attestation.effects],
            "refusal": (
                None
                if refusal is None
                else {
                    "reason": str(refusal.reason),
                    "detail": refusal.detail,
                    "warrant": None if refusal.warrant is None else str(refusal.warrant),
                    "subject_message": refusal.subject_message,
                    "metadata": dict(refusal.metadata),
                }
            ),
            "cost": {
                "input_tokens": attestation.cost.input_tokens,
                "output_tokens": attestation.cost.output_tokens,
                "cached_tokens": attestation.cost.cached_tokens,
                "currency": attestation.cost.currency,
                "amount": attestation.cost.amount,
                "pricing_version": attestation.cost.pricing_version,
            },
            "seal": None if seal is None else AuditEventCodec.dump_seal(seal),
            "supersedes": None if attestation.supersedes is None else str(attestation.supersedes),
            "metadata": _Values.dump_mapping(attestation.metadata, where="metadata"),
        }

    @classmethod
    def decode(cls, payload: bytes) -> Attestation:
        """Rebuild an attestation, **and verify it is the one that was written.**

        The recomputed content hash is compared against the envelope's. A mismatch is
        an integrity failure, not a parsing detail: it means the bytes were altered,
        or that this build's value objects no longer agree with the ones that produced
        the record.
        """
        form = cls.parse(payload, what="attestation")
        try:
            return cls.from_form(form)
        except CodecError:
            raise
        except Exception as exc:
            # Everything, not only the parse errors. A stored payload is untrusted
            # input: 60,000 nested objects raised RecursionError straight out of
            # json.loads, and a `payload` field holding a list raised AttributeError
            # from .items(). Neither was a CodecError, so StoredChainCheck — which
            # catches CodecError to report ALTERED_EVENT — did not catch them, and the
            # verification sweep crashed instead of reporting tampering.
            raise CodecError(
                f"attestation payload could not be decoded: {type(exc).__name__}: {exc}"
            ) from exc

    @classmethod
    def from_form(cls, form: Mapping[str, Any]) -> Attestation:
        cls._assert_readable(form)
        refusal = form.get("refusal")
        seal = form.get("seal")
        cost = form.get("cost") or {}
        structured = form.get("structured")
        supersedes = form.get("supersedes")

        attestation = Attestation(
            run_id=RunId(form["run_id"]),
            verdict=Verdict(form["verdict"]),
            context=_Context.load(form["context"]),
            created_at=_Times.require(form["created_at"], field="created_at"),
            answer=form.get("answer", ""),
            structured=None if structured is None else _Values.load_mapping(structured),
            warrants=_Warrants.load(form.get("warrants", {})),
            effects=tuple(_Effects.load(record) for record in form.get("effects", ())),
            refusal=(
                None
                if refusal is None
                else Refusal(
                    reason=RefusalReason(refusal["reason"]),
                    detail=refusal["detail"],
                    warrant=(
                        None if refusal.get("warrant") is None else WarrantKind(refusal["warrant"])
                    ),
                    subject_message=refusal.get("subject_message"),
                    metadata=dict(refusal.get("metadata", {})),
                )
            ),
            cost=CostRecord(
                input_tokens=cost.get("input_tokens", 0),
                output_tokens=cost.get("output_tokens", 0),
                cached_tokens=cost.get("cached_tokens", 0),
                currency=cost.get("currency", "USD"),
                amount=cost.get("amount", "0"),
                pricing_version=cost.get("pricing_version"),
            ),
            seal=None if seal is None else AuditEventCodec.load_seal(seal),
            supersedes=None if supersedes is None else RunId(supersedes),
            metadata=_Values.load_mapping(form.get("metadata", {})),
        )

        recorded = form.get("content_hash")
        recomputed = str(attestation.content_hash())
        if recorded != recomputed:
            raise CodecError(
                f"attestation {attestation.run_id!r} does not match its recorded content "
                f"hash: stored {recorded!r}, recomputed {recomputed!r}. Either the "
                f"payload was altered, or this build's value objects disagree with the "
                f"ones that wrote it. Both are integrity failures; neither is a record "
                f"that may be relied on."
            )
        return attestation

    @classmethod
    def _assert_readable(cls, form: Mapping[str, Any]) -> None:
        if form.get("format") != cls.FORMAT:
            raise CodecError(f"payload declares format {form.get('format')!r}, not {cls.FORMAT!r}")
        version = form.get("version")
        if version not in cls.READABLE:
            raise CodecError(
                f"attestation format version {version!r} cannot be read by this build "
                f"(readable: {sorted(cls.READABLE)}). Refusing rather than guessing: a "
                f"major release must ship a shim that verifies prior-major "
                f"attestations, and this is where the absence of one shows up."
            )


class AuditEventCodec(_Codec):
    """Encodes audit events and run seals.

    Separate from the attestation codec because events are written one at a time on the
    hot path, long before an attestation exists to hold them.
    """

    FORMAT: ClassVar[str] = "attest.audit_event"
    VERSION: ClassVar[int] = 1
    READABLE: ClassVar[frozenset[int]] = frozenset({1})

    @classmethod
    def encode(cls, event: AuditEvent) -> bytes:
        """Canonical bytes for ``event``. See :meth:`AttestationCodec.encode` on why
        this serialises the form rather than re-canonicalising it."""
        return Canonical.encode_form(cls.to_form(event))

    @classmethod
    def to_form(cls, event: AuditEvent) -> dict[str, Any]:
        return {
            "format": cls.FORMAT,
            "version": cls.VERSION,
            "run_id": str(event.run_id),
            "event_type": event.event_type,
            "occurred_at": _Times.dump(event.occurred_at),
            "payload": _Values.dump_mapping(
                event.payload, where=f"event[{event.event_type!r}].payload"
            ),
            "event_id": event.event_id,
            "parent_event_id": event.parent_event_id,
            "branch": event.branch,
            "sequence": event.sequence,
            "previous_hash": None if event.previous_hash is None else str(event.previous_hash),
        }

    @classmethod
    def decode(cls, payload: bytes) -> AuditEvent:
        form = cls.parse(payload, what="audit event")
        try:
            return cls.from_form(form)
        except CodecError:
            raise
        except Exception as exc:
            # A `payload` field holding a list raised AttributeError out of .items(),
            # which is not a CodecError — so StoredChainCheck, which catches CodecError
            # to report ALTERED_EVENT, crashed the verification sweep instead of
            # reporting the row as altered. An attacker who can INSERT an audit row
            # (the append-only trigger permits inserts) could therefore stop the sweep
            # rather than be caught by it.
            raise CodecError(
                f"audit event payload could not be decoded: {type(exc).__name__}: {exc}"
            ) from exc

    @classmethod
    def from_form(cls, form: Mapping[str, Any]) -> AuditEvent:
        if form.get("format") != cls.FORMAT:
            raise CodecError(f"payload declares format {form.get('format')!r}, not {cls.FORMAT!r}")
        if form.get("version") not in cls.READABLE:
            raise CodecError(
                f"audit event format version {form.get('version')!r} cannot be read by "
                f"this build (readable: {sorted(cls.READABLE)})"
            )
        previous = form.get("previous_hash")
        return AuditEvent(
            run_id=RunId(form["run_id"]),
            event_type=form["event_type"],
            occurred_at=_Times.require(form["occurred_at"], field="event.occurred_at"),
            payload=_Values.load_mapping(cls._mapping(form.get("payload", {}), "payload")),
            event_id=cast("str | None", form.get("event_id")),
            parent_event_id=form.get("parent_event_id"),
            branch=form.get("branch"),
            sequence=form.get("sequence"),
            previous_hash=None if previous is None else Hash(previous),
        )

    @staticmethod
    def _mapping(value: Any, field: str) -> Mapping[str, Any]:
        """Structural check before use. A list here used to raise AttributeError."""
        if not isinstance(value, dict):
            raise CodecError(f"audit event {field} is {type(value).__name__}, not an object")
        return value

    @staticmethod
    def dump_seal(seal: RunSeal) -> dict[str, Any]:
        return {
            "run_id": str(seal.run_id),
            "event_count": seal.event_count,
            "first_sequence": seal.first_sequence,
            "last_sequence": seal.last_sequence,
            "head_hash": str(seal.head_hash),
            "attestation_hash": str(seal.attestation_hash),
            "sealed_at": _Times.dump(seal.sealed_at),
            "signer": seal.signer,
            "signature": seal.signature,
        }

    @staticmethod
    def load_seal(form: Mapping[str, Any]) -> RunSeal:
        return RunSeal(
            run_id=RunId(form["run_id"]),
            event_count=form["event_count"],
            first_sequence=form["first_sequence"],
            last_sequence=form["last_sequence"],
            head_hash=Hash(form["head_hash"]),
            attestation_hash=Hash(form["attestation_hash"]),
            sealed_at=_Times.require(form["sealed_at"], field="seal.sealed_at"),
            signer=form.get("signer"),
            signature=form.get("signature"),
        )
