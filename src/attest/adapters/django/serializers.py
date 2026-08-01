"""DRF serialisers that cannot drop the verdict or the warnings.

The hazard is specific and it is not hypothetical: an ``ALLOW_WITH_WARNINGS`` figure
rendered into a dashboard that shows only the figure is a material misstatement
delivered with a clean conscience. The usual sparse-fields pattern — ``?fields=answer``
— is exactly how that happens, one reasonable-looking optimisation at a time.

So the mandatory fields are re-added after any restriction, and re-added again on the
way out. This adapter cannot force a frontend to display them. It can refuse to make
their omission the default, and refuse to provide the mechanism that removes them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rest_framework import serializers

from attest.adapters.django.models import AttestationRecord, PendingAction
from attest.assurance.export import DisclosureProfile
from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["AttestationSerializer", "PendingActionSerializer", "RunResultSerializer"]


class AttestationSerializer(serializers.ModelSerializer):
    """One attestation, with its verdict and warnings structurally unremovable.

    **Disclosure-aware, because the dispatch response was and this was not.**
    ``RunResultSerializer`` carefully withheld finding messages and the operator-facing
    refusal detail from non-operator profiles; this one had no disclosure concept at
    all and always serialised ``warnings`` — which the store populates from the *same*
    finding messages. So one extra ``GET /attestations/{run_id}/`` defeated the whole
    control, and returned text like ``"capability:settle_claim: actor 'ops-7' does not
    hold 'settle_claim'"``: internal actor identifiers, capability names, and the
    system's reasoning about the person, to every authenticated tenant user.

    Under the subject default the warnings are reduced to their codes — enough to
    count, categorise, alert on and contest, without narrating the decision back.
    """

    #: Present in every representation, whatever the caller asked for.
    MANDATORY: ClassVar[tuple[str, ...]] = ("run_id", "verdict", "warnings", "is_final")

    requires_human_attention = serializers.SerializerMethodField()

    class Meta:
        model = AttestationRecord
        fields = (
            "run_id",
            "tenant_id",
            "verdict",
            "requires_human_attention",
            "warnings",
            "answer",
            "content_hash",
            "is_final",
            "sealed",
            "created_at",
            "supersedes",
            "superseded_by",
        )
        read_only_fields = fields

    def __init__(
        self,
        *args: Any,
        fields: Sequence[str] | None = None,
        disclosure: DisclosureProfile = DisclosureProfile.SUBJECT,
        **kwargs: Any,
    ) -> None:
        """Restrict the output, but never below the mandatory set.

        ``disclosure`` defaults to the narrowest audience, matching
        ``DispatchView.disclosure_for``. An operator console passes ``INTERNAL``.
        """
        super().__init__(*args, **kwargs)
        self.disclosure = disclosure
        if fields is None:
            return
        keep = set(fields) | set(self.MANDATORY)
        for name in set(self.fields) - keep:
            self.fields.pop(name)

    @property
    def operator(self) -> bool:
        return self.disclosure in (DisclosureProfile.INTERNAL, DisclosureProfile.REGULATOR)

    def get_requires_human_attention(self, instance: AttestationRecord) -> bool | None:
        """Whether this verdict is one a person must look at.

        ``None`` where the stored string is not a verdict this version knows. Returning
        ``False`` for an unrecognised value would be the framework asserting an
        all-clear it cannot support — the precise failure mode it exists to prevent.
        """
        try:
            return Verdict(instance.verdict).requires_human_attention
        except ValueError:
            return None

    def to_representation(self, instance: AttestationRecord) -> dict[str, Any]:
        data: dict[str, Any] = dict(super().to_representation(instance))
        for name in self.MANDATORY:
            if name not in data:
                data[name] = getattr(instance, name)
        if not self.operator and "warnings" in data:
            # A warning a caller cannot see is a warning that does not exist, so the
            # count and the categories survive. What does not is the operator-facing
            # text, which names actors and capabilities.
            data["warnings"] = [self.code_of(message) for message in data["warnings"]]
        return data

    @staticmethod
    def code_of(message: str) -> str:
        """``"kind:code: detail"`` reduced to ``"kind:code"``. Never the detail."""
        head, _, _ = str(message).partition(": ")
        return head or "qualified"


class PendingActionSerializer(serializers.ModelSerializer):
    """One pending decision, including the hash of what is actually being approved.

    ``action_hash`` is mandatory for the same reason grants bind to arguments rather
    than tool names: an approval screen showing only ``transfer_funds`` is asking
    someone to authorise an amount and a destination they were never shown.
    """

    MANDATORY: ClassVar[tuple[str, ...]] = ("approval_id", "action_hash", "expires_at", "state")

    class Meta:
        model = PendingAction
        fields = (
            "approval_id",
            "run_id",
            "tenant_id",
            "grant_id",
            "action_hash",
            "summary",
            "state",
            "opened_at",
            "expires_at",
            "resolved_at",
            "approver",
        )
        read_only_fields = fields

    def to_representation(self, instance: PendingAction) -> dict[str, Any]:
        data: dict[str, Any] = dict(super().to_representation(instance))
        for name in self.MANDATORY:
            if name not in data:
                data[name] = getattr(instance, name)
        return data


class RunResultSerializer(serializers.Serializer):
    """A run's attestation, rendered straight from the kernel object.

    Separate from :class:`AttestationSerializer` because that one reads a database row
    and this one reads the record the engine just produced — a dispatch response must
    not depend on the write having landed first.

    ``verdict``, ``warnings`` and ``warrants`` are built here rather than declared as
    optional fields, so there is no ``fields`` argument, no serialiser subclass and no
    view configuration that can omit them. A caller reading only ``answer`` has to
    ignore them deliberately; the API will not do it for them.

    .. rubric:: Disclosure defaults to the narrowest audience

    A refusal carries two texts, for two different audiences: ``detail`` explains the
    decision to an operator, and ``subject_message`` is what the person it concerns
    may read. Returning ``detail`` over an API a subject can reach hands them the
    system's internal reasoning — including, for an authority refusal, the name of a
    capability and who does not hold it.

    So ``disclosure`` defaults to :attr:`DisclosureProfile.SUBJECT`: the verdict, the
    warnings, and the subject-facing wording. An operator console opts into
    ``INTERNAL`` explicitly. Fail-closed is the only safe default when the class does
    not know who is on the other end of the socket.
    """

    #: Profiles that may see internal reasoning: verifier refs, finding messages, and
    #: the refusal's operator-facing detail.
    OPERATOR_PROFILES: ClassVar[frozenset[DisclosureProfile]] = frozenset(
        {DisclosureProfile.INTERNAL, DisclosureProfile.REGULATOR, DisclosureProfile.LITIGATION}
    )

    def __init__(
        self,
        *args: Any,
        disclosure: DisclosureProfile = DisclosureProfile.SUBJECT,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.disclosure = disclosure

    @property
    def operator(self) -> bool:
        return self.disclosure in self.OPERATOR_PROFILES

    def to_representation(self, instance: Any) -> dict[str, Any]:
        return {
            "run_id": str(instance.run_id),
            "verdict": instance.verdict.value,
            "requires_human_attention": instance.verdict.requires_human_attention,
            "answer": instance.answer,
            "structured": None if instance.structured is None else dict(instance.structured),
            "warnings": self.warnings_of(instance),
            "warrants": {
                str(kind): self._warrant(report)
                for kind, report in sorted(instance.warrants.items())
            },
            "effects": [
                {
                    "tool": record.action.tool,
                    "state": record.state.value,
                    "external_reference": record.external_reference,
                    "grant_id": None if record.grant_id is None else str(record.grant_id),
                    "detail": record.detail,
                }
                for record in instance.effects
            ],
            "refusal": self._refusal(instance.refusal),
            "is_final": instance.is_final,
            "sealed": instance.seal is not None,
            "content_hash": str(instance.content_hash()),
            "created_at": instance.created_at.isoformat(),
        }

    def _warrant(self, report: Any) -> dict[str, Any]:
        """Status and satisfaction always; the reasoning only for an operator.

        Whether a warrant held is the caller's business in every profile — that is the
        qualification they must not be able to drop. *Why* it did not hold is the
        system's reasoning about a person, and is not.
        """
        rendered: dict[str, Any] = {
            "status": report.status.value,
            "satisfied": report.satisfied,
        }
        if self.operator:
            rendered["verifier_ref"] = report.verifier_ref
            rendered["findings"] = [
                {
                    "code": finding.code,
                    "message": finding.message,
                    "severity": finding.severity.value,
                }
                for finding in report.findings
            ]
        else:
            # Codes without messages: enough to count, categorise and alert on,
            # without narrating the decision back to its subject.
            rendered["findings"] = [
                {"code": finding.code, "severity": finding.severity.value}
                for finding in report.findings
            ]
        return rendered

    def _refusal(self, refusal: Any) -> dict[str, Any] | None:
        if refusal is None:
            return None
        rendered: dict[str, Any] = {
            "reason": str(refusal.reason),
            "warrant": None if refusal.warrant is None else str(refusal.warrant),
            "subject_message": refusal.subject_message,
        }
        if self.operator:
            rendered["detail"] = refusal.detail
        return rendered

    def warnings_of(self, instance: Any) -> list[str]:
        """The qualifications the caller gets, at the right level of detail.

        Two rules meet here and both survive. *A warning a caller cannot see is a
        warning that does not exist* — so a qualification is never withheld entirely.
        And *a subject is not shown the system's reasoning about them* — so the
        operator-facing message is not what they are shown.

        Withholding the finding messages inside ``warrants`` while re-emitting every
        one of them at the top level was the hole here, and it leaked the sharpest
        text in the system: the authority report builds its messages from
        ``CapabilityCheck.detail``, which names the actor and the capability.

        Under an operator profile these are the messages. Under the subject default
        they are ``kind:code`` pairs — enough to count, categorise, alert on and
        contest, without narrating the decision back to the person it was about.

        Which findings count is :meth:`WarrantReport.qualifications`, so this and the
        store's column cannot disagree about what a warning is.
        """
        if self.operator:
            return [
                message
                for report in instance.warrants.values()
                for message in report.qualifications()
            ]
        return [
            f"{report.kind}:{finding.code}"
            for report in instance.warrants.values()
            for finding in report.findings
            if finding.severity in (Severity.WARNING, Severity.ERROR)
        ]
