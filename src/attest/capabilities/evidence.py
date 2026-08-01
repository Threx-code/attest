"""Evidence verification — does the cited support exist, and is it unaltered?

Deliberately answers only the mechanical half. Whether the evidence *entails* the
claim is semantic, costly and probabilistic, and lives in :mod:`.judging`. Merging
the two is how "verified" comes to mean nothing.

Every verifier is fail-closed: one that raises yields UNVERIFIABLE, never PASS.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from attest.kernel.evidence import (
    AuthorityLevel,
    EvidenceKinds,
    Persistence,
    SupportResult,
    VerificationOutcome,
)
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import date

    from attest.kernel.evidence import Evidence, EvidenceKind

__all__ = [
    "ComputationVerifier",
    "DerivationVerifier",
    "EvidenceEngine",
    "ObservationVerifier",
    "QuotedSpanVerifier",
    "RecordValueVerifier",
    "SourceResolver",
    "SupportVerifier",
    "VerifierRegistry",
]


@runtime_checkable
class SourceResolver(Protocol):
    """Fetches the source a piece of evidence claims to come from.

    This port exists because of the defect it closes. Every verifier here used to
    compare the evidence against a value carried in **the same object's own metadata** —
    ``source_text``, ``recorded_value``, ``recomputed`` — so whoever constructed the
    evidence supplied both the claim and the proof of the claim. A fabricated citation
    to a statute that does not exist verified perfectly.

    Hashing the self-supplied text against the self-supplied ``integrity_hash`` does not
    fix it either: the attacker controls both. The source has to come from somewhere the
    author of the evidence does not control, and that is what this is.

    **Contract: return the bytes as they were at that version, or ``None``.** Returning
    today's bytes for a historical version answers a different question, and a verifier
    that got a pass out of it would be reporting on the wrong document.
    """

    def fetch(self, source_id: str, version: str) -> bytes | None: ...


@runtime_checkable
class SupportVerifier(Protocol):
    """Re-checks one kind of evidence against its source.

    ``source`` is the resolved bytes, or ``None`` when the source could not be
    reached. ``None`` must produce ``UNVERIFIABLE`` — never ``PASS``, and never a
    comparison against something the evidence carried itself.
    """

    @property
    def kind(self) -> EvidenceKind: ...

    def verify(
        self, evidence: Evidence, *, at: date, source: bytes | None = None
    ) -> SupportResult: ...


@dataclass(frozen=True, slots=True)
class QuotedSpanVerifier:
    """The exact substring is still present at that offset in that source version.

    Requires the retrieved text to be carried on the evidence. Where persistence is
    REFERENCE the text is absent, and the honest answer is UNVERIFIABLE rather than a
    pass obtained by re-fetching whatever the source says today.
    """

    kind: EvidenceKind = EvidenceKinds.QUOTED_SPAN

    def verify(self, evidence: Evidence, *, at: date, source: bytes | None = None) -> SupportResult:
        quote = evidence.value
        if not isinstance(quote, str):
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy=f"quoted span is {type(quote).__name__}, not text",
            )
        source_text = self.source_text(evidence, source)
        if source_text is None:
            # No resolvable source. UNVERIFIABLE is what this actually establishes;
            # the old code read `metadata["source_text"]` here, which let the author of
            # the citation supply the document it was checked against.
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)

        offset = evidence.metadata.get("char_start")
        if isinstance(offset, int):
            actual = source_text[offset : offset + len(quote)]
            if actual != quote:
                return SupportResult(
                    supported=False,
                    outcome=VerificationOutcome.FAIL,
                    discrepancy=f"offset {offset} holds {actual!r}, cited {quote!r}",
                )
            return SupportResult(supported=True, outcome=VerificationOutcome.PASS)

        if quote not in source_text:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy="quoted text is not present in the source",
            )
        return SupportResult(supported=True, outcome=VerificationOutcome.PASS)

    @staticmethod
    def source_text(evidence: Evidence, source: bytes | None) -> str | None:
        """The document text, if it can be obtained from outside the evidence.

        Two routes, and both are checked against ``integrity_hash``:

        - **Resolved** bytes from a :class:`SourceResolver`. Independent of the author.
        - **Embedded** bytes, but only where ``persistence is EMBEDDED`` *and* they hash
          to the recorded integrity hash. Embedding is the tier that means "the bytes
          travel with the record", and the hash is what pins them — a record whose
          embedded bytes were swapped fails here rather than verifying against itself.

        ``metadata["source_text"]`` is deliberately not a route. It is neither resolved
        nor hashed, and accepting it is the whole of ATT-33.
        """
        from attest.kernel.canonical import Canonical

        raw = source
        if raw is None and evidence.persistence is Persistence.EMBEDDED:
            embedded = evidence.metadata.get("embedded_source")
            if isinstance(embedded, bytes):
                raw = embedded
        if raw is None:
            return None
        if Canonical.digest_bytes(raw) != str(evidence.source.integrity_hash):
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None


@dataclass(frozen=True, slots=True)
class RecordValueVerifier:
    """Field F of record R at version V still equals X.

    UNVERIFIABLE is the common answer here, and it is the honest one: many source
    systems are last-write-wins and cannot answer "what did this field say at version
    7". Checking the current value instead would be a pass obtained by changing the
    question.
    """

    kind: EvidenceKind = EvidenceKinds.RECORD_VALUE

    def verify(self, evidence: Evidence, *, at: date, source: bytes | None = None) -> SupportResult:
        if source is None:
            # `metadata["recorded_value"]` used to answer this, which meant the record
            # was checked against a copy of itself supplied by whoever cited it.
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        recorded = self.recorded_value(source)
        if recorded is None:
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        if recorded != evidence.value:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy=f"record now holds {recorded!r}, cited {evidence.value!r}",
            )
        return SupportResult(supported=True, outcome=VerificationOutcome.PASS)

    @staticmethod
    def recorded_value(source: bytes) -> object | None:
        """The value the source system returned. Decoded, never re-interpreted.

        A resolver hands back the canonical encoding of what the record held at that
        version; anything that does not decode is UNVERIFIABLE rather than a mismatch,
        because "we could not read the answer" and "the answer is different" are
        different findings and an auditor needs them apart.
        """
        import json

        from attest.kernel.canonical import Canonical

        try:
            revived: object = Canonical.revive(json.loads(source.decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            return None
        else:
            return revived


@dataclass(frozen=True, slots=True)
class ComputationVerifier:
    """Re-running the model over pinned inputs reproduces the output.

    A mismatch is a genuine finding rather than a false alarm: if the model was
    retrained, the historical output is no longer reproducible and that is exactly
    what an auditor needs to be told.
    """

    kind: EvidenceKind = EvidenceKinds.COMPUTATION

    def verify(self, evidence: Evidence, *, at: date, source: bytes | None = None) -> SupportResult:
        if source is None:
            # Re-running the model is the resolver's job. Reading `metadata["recomputed"]`
            # meant the attestation re-ran nothing and compared the output to itself.
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        recomputed = RecordValueVerifier.recorded_value(source)
        if recomputed is None:
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        if recomputed != evidence.value:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy=(
                    f"re-running produced {recomputed!r}, the attestation cites "
                    f"{evidence.value!r}; the model or its inputs have changed"
                ),
            )
        return SupportResult(supported=True, outcome=VerificationOutcome.PASS)


@dataclass(frozen=True, slots=True)
class ObservationVerifier:
    """A measurement, within its device's calibration window.

    Calibration is part of verification, not metadata: a reading from an
    out-of-calibration instrument is not evidence of anything.
    """

    kind: EvidenceKind = EvidenceKinds.OBSERVATION

    def verify(self, evidence: Evidence, *, at: date, source: bytes | None = None) -> SupportResult:
        if source is None:
            # A device's calibration state is held by the device registry, not by the
            # reading. Trusting `metadata["calibration_valid"]` let a reading assert its
            # own instrument was in calibration.
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        if evidence.metadata.get("calibration_valid") is False:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy="instrument was outside its calibration window",
            )
        if "device_id" not in evidence.metadata:
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        return SupportResult(supported=True, outcome=VerificationOutcome.PASS)


@dataclass(frozen=True, slots=True)
class DerivationVerifier:
    """The stated operation over cited sub-evidence yields the stated result.

    Verifies structurally: a derivation with no sub-evidence supports nothing, and one
    whose children fail cannot itself pass. Arithmetic correctness of the operation is
    a domain concern — the framework cannot know what "reconciles" means.
    """

    kind: EvidenceKind = EvidenceKinds.DERIVATION

    def verify(
        self,
        evidence: Evidence,
        *,
        at: date,
        source: bytes | None = None,
        children: Sequence[SupportResult] = (),
    ) -> SupportResult:
        """Structural only, but the structure now includes the children's results.

        This used to return PASS whenever ``sub_evidence`` was non-empty — a derivation
        verified by *counting* its children. A failing leaf was laundered into a passing
        total, which is the exact shape the reporting domain uses for every aggregate.
        """
        if not evidence.sub_evidence:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy="derivation cites no sub-evidence, so it derives from nothing",
            )
        failed = [r for r in children if r.outcome is VerificationOutcome.FAIL]
        if failed:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.FAIL,
                discrepancy=(
                    f"{len(failed)} of {len(children)} cited sub-evidence items failed; "
                    f"a total cannot be better supported than the figures it sums"
                ),
            )
        unverifiable = [r for r in children if r.outcome is VerificationOutcome.UNVERIFIABLE]
        if unverifiable:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.UNVERIFIABLE,
                discrepancy=(
                    f"{len(unverifiable)} of {len(children)} cited sub-evidence items "
                    f"could not be checked, so neither can this derivation"
                ),
            )
        return SupportResult(supported=True, outcome=VerificationOutcome.PASS)


class VerifierRegistry:
    """Maps evidence kinds to verifiers.

    An unregistered kind is UNVERIFIABLE, never assumed verified. That is the
    fail-closed default the conformance kit checks: a domain that adds a kind without
    a verifier gets no support from it rather than free support.
    """

    def __init__(self, verifiers: Sequence[SupportVerifier] = ()) -> None:
        self._by_kind: dict[EvidenceKind, SupportVerifier] = {v.kind: v for v in verifiers}

    def register(self, verifier: SupportVerifier) -> None:
        self._by_kind[verifier.kind] = verifier

    @classmethod
    def with_defaults(cls) -> VerifierRegistry:
        """The five shipped strategies. Only one of them is document-shaped."""
        return cls(
            (
                QuotedSpanVerifier(),
                RecordValueVerifier(),
                ComputationVerifier(),
                ObservationVerifier(),
                DerivationVerifier(),
            )
        )

    def verify(
        self,
        evidence: Evidence,
        *,
        at: date,
        source: bytes | None = None,
        children: Sequence[SupportResult] = (),
    ) -> SupportResult:
        verifier = self._by_kind.get(evidence.kind)
        if verifier is None:
            return SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
        try:
            if isinstance(verifier, DerivationVerifier):
                return verifier.verify(evidence, at=at, source=source, children=children)
            return verifier.verify(evidence, at=at, source=source)
        except Exception as exc:
            return SupportResult(
                supported=False,
                outcome=VerificationOutcome.UNVERIFIABLE,
                discrepancy=f"verifier raised {type(exc).__name__}: {exc}",
            )


class EvidenceEngine:
    """Verifies cited evidence and produces the epistemic warrant.

    Holds the verifier registry, the resolver and the authority floor, so a domain
    swaps behaviour by constructing a different engine rather than by threading
    arguments through every call site.

    **Without a resolver, document-shaped evidence is UNVERIFIABLE rather than
    verified.** That is a deliberate and visible downgrade. The alternative — which is
    what this class used to do — is to let every verifier compare the evidence against a
    key in its own metadata, so a fabricated citation to a statute that does not exist
    passes. An honest UNVERIFIABLE is a finding somebody can act on; a dishonest PASS is
    not.
    """

    __slots__ = ("_authority_for", "_registry", "_required_authority", "_resolver")

    def __init__(
        self,
        registry: VerifierRegistry | None = None,
        *,
        required_authority: AuthorityLevel = AuthorityLevel.ADVISORY,
        resolver: SourceResolver | None = None,
        authority_for: Callable[[str], AuthorityLevel] | None = None,
    ) -> None:
        self._registry = registry if registry is not None else VerifierRegistry.with_defaults()
        self._required_authority = required_authority
        self._resolver = resolver
        self._authority_for = authority_for
        """The profile's per-claim floor.

        A fixed floor meant a domain that raised its requirement to AUTHORITATIVE for
        sanctions determinations still got ADVISORY, because nothing consulted the
        profile on the run path. Passed as a callable rather than the whole profile so
        this layer does not import one.
        """

    @property
    def registry(self) -> VerifierRegistry:
        return self._registry

    @property
    def resolver(self) -> SourceResolver | None:
        return self._resolver

    def floor_for(self, evidence: Evidence) -> AuthorityLevel:
        """The authority this item must carry. The profile decides when it can.

        **A profile that raises gets the strictest floor, not the weakest.** ATT-65.

        The success path takes ``max(declared, required)`` — the stricter of the two,
        because a domain may raise its requirement and may not lower it. The failure
        path returned ``self._required_authority``, which is by construction the weaker
        one. So an exception inside a domain's policy *relaxed* the check: a
        ``KeyError`` in a lookup table, a typo in a claim kind, a config reload halfway
        through, and evidence that should have needed an AUTHORITATIVE source was
        admitted at ADVISORY. Nothing reported it, because from the caller's side a
        lower floor looks exactly like a permissive profile.

        That is the one direction ``docs/capabilities/guards.md`` forbids, and it is the
        defect class the audit found in every surveyed codebase: ``except Exception:``
        followed by the permissive answer.

        AUTHORITATIVE rather than propagating, deliberately. A profile whose policy is
        broken should not take the whole run down — the run still has a verdict to
        reach, and it should reach it by refusing evidence it cannot vouch for. The
        run therefore fails the epistemic warrant with a finding naming the profile,
        which is visible and contestable, where a propagated exception is a 500 and a
        retry.
        """
        if self._authority_for is None:
            return self._required_authority
        try:
            declared = self._authority_for(str(evidence.kind))
        except Exception:
            return AuthorityLevel.AUTHORITATIVE
        return max(declared, self._required_authority, key=lambda level: level.rank)

    def verify(self, evidence: Evidence, *, at: date) -> SupportResult:
        """Verify one item **and everything beneath it**."""
        return self._verify_tree(evidence, at=at)[0]

    def _verify_tree(self, evidence: Evidence, *, at: date) -> tuple[SupportResult, list[Finding]]:
        """Depth-first, children before parents.

        ``evaluate`` used to iterate the top-level sequence only, so a derivation's
        children were never handed to any verifier at all — a tree of 412 fabricated
        leaves was "verified" by checking that the parent had children. The recursion is
        bounded by the same node budget that bounds construction, which is what makes
        that budget load-bearing rather than decorative.
        """
        findings: list[Finding] = []
        child_results: list[SupportResult] = []
        for child in evidence.sub_evidence:
            result, child_findings = self._verify_tree(child, at=at)
            child_results.append(result)
            findings.extend(child_findings)

        result = self._registry.verify(
            evidence, at=at, source=self._fetch(evidence), children=tuple(child_results)
        )
        findings.extend(self._findings_for(evidence, result, at=at))
        return result, findings

    def _fetch(self, evidence: Evidence) -> bytes | None:
        """Resolve the source. A resolver that raises is an unreachable source.

        Not a verification failure: "we could not reach the record system" and "the
        record says something else" are different findings, and collapsing them would
        make an outage look like forgery.
        """
        if self._resolver is None:
            return None
        try:
            return self._resolver.fetch(evidence.source.source_id, evidence.source.version or "")
        except Exception:
            return None

    def _findings_for(self, item: Evidence, result: SupportResult, *, at: date) -> list[Finding]:
        """Everything that disqualifies one item: support, authority, and currency."""
        findings: list[Finding] = []
        if not result.supported:
            findings.append(
                Finding(
                    code=f"support_{result.outcome.value}",
                    message=result.discrepancy or f"{item.evidence_id}: {result.outcome.value}",
                    severity=Severity.ERROR,
                    data={"evidence_id": str(item.evidence_id), "kind": str(item.kind)},
                )
            )
        floor = self.floor_for(item)
        if not item.source.authority.at_least(floor):
            findings.append(
                Finding(
                    code="insufficient_source_authority",
                    message=(
                        f"{item.source.source_id} is {item.source.authority.value}, "
                        f"below the required {floor.value}. The content may be genuine "
                        f"and the source still not entitled to state it."
                    ),
                    severity=Severity.ERROR,
                    data={"evidence_id": str(item.evidence_id)},
                )
            )
        if not item.source.validity.covers(at):
            # ValidityWindow was implemented, correct, and called by nothing. A clinical
            # guideline replaced in 2020 cited for a 2026 decision passed the warrant —
            # the right decision's shape with the wrong decision's content, and a
            # verifiable citation attached to it.
            findings.append(
                Finding(
                    code="evidence_out_of_validity",
                    message=(
                        f"{item.source.source_id} version {item.source.version!r} was not "
                        f"in force on {at.isoformat()} (window "
                        f"{item.source.validity.effective_from}..{item.source.validity.effective_to}). "
                        f"Stale evidence with a verifiable citation is the most dangerous "
                        f"shape a wrong decision takes."
                    ),
                    severity=Severity.ERROR,
                    data={"evidence_id": str(item.evidence_id)},
                )
            )
        return findings

    def evaluate(self, evidence: Sequence[Evidence], *, at: date) -> WarrantReport:
        """Produce the epistemic warrant over a set of evidence, and its whole tree.

        Checks **four independent things**, and a pass requires all of them: that the
        content is unaltered *against a source the citing party does not control*, that
        the source was entitled to state it, that it was in force on the relevant date,
        and that everything it derives from passes too.
        """
        if not evidence:
            return WarrantReport(
                kind=WarrantKinds.EPISTEMIC,
                status=WarrantStatus.EVALUATED,
                satisfied=False,
                findings=(
                    Finding(
                        code="no_evidence",
                        message="no evidence was cited",
                        severity=Severity.ERROR,
                    ),
                ),
            )

        findings: list[Finding] = []
        for item in evidence:
            _, item_findings = self._verify_tree(item, at=at)
            findings.extend(item_findings)

        return WarrantReport(
            kind=WarrantKinds.EPISTEMIC,
            status=WarrantStatus.EVALUATED,
            satisfied=not findings,
            findings=tuple(findings),
        )
