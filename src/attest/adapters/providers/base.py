"""Shared provider machinery — lazy SDK loading, turn mapping, honest failure.

Three properties are enforced here rather than left to each backend:

**The SDK is imported inside a method, never at module scope.** The base install must
pull nothing, and a CI job asserts it: a top-level ``import anthropic`` in this package
would fail that job the moment the wheel is installed into a clean environment. It
would also fail *at import time* for every user who installed a different extra.

**An empty completion is an error, not an answer.** A truncated, filtered or refused
response that is returned as a zero-length string is the exact failure this framework
exists to prevent — an unverified result presented as a definitive one. Every backend
here raises instead.

**Sampling parameters are omitted where the model rejects them.** Current reasoning
models return HTTP 400 for ``temperature``. Sending it anyway would make the gateway
unusable on the models it most wants to route to, and stripping it silently while
claiming the request was honoured would be worse — so the response records that
sampling was model-controlled.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, ClassVar

from attest.capabilities.gateway import CompletionResponse, ProviderSpec
from attest.kernel.errors import AttestError, ConfigurationError

from .families import ModelFamilies

if TYPE_CHECKING:
    from collections.abc import Mapping

    from attest.capabilities.gateway import CompletionRequest, Feature

__all__ = [
    "BaseProvider",
    "ChatCompletionsProvider",
    "ProviderError",
    "ProviderRefused",
    "ProviderUnavailable",
]


class ProviderError(AttestError):
    """A provider could not produce a usable completion.

    An exception rather than a refusal: the gateway, not the backend, decides whether
    a failed call becomes a failover, a retry or a refused run. A backend that
    returned an empty :class:`~attest.capabilities.gateway.CompletionResponse` would
    have made that decision silently, and made it wrong.
    """


class ProviderUnavailable(ProviderError):
    """The backend's SDK is not installed.

    Carries the exact ``pip install`` line, because the alternative — a bare
    ``ModuleNotFoundError`` from six frames down — makes an optional extra look like
    a broken package.
    """


class ProviderRefused(ProviderError):
    """The provider itself declined the request.

    Distinct from a transport failure: retrying the same request on the same model
    will decline again, so a gateway that treats this as a transient error burns its
    retry budget for nothing. The declining model and its stated category are carried
    so the gateway can route to a different family rather than a different endpoint.
    """

    def __init__(self, message: str, *, provider: str, model_id: str, category: str = "") -> None:
        super().__init__(message)
        self.provider = provider
        self.model_id = model_id
        self.category = category


class BaseProvider:
    """One provider backend, satisfying the gateway's ``LLMProvider`` protocol.

    Subclasses supply :attr:`SDK_MODULE`, :meth:`_build_client` and :meth:`complete`.
    Everything else — residency metadata, family resolution, turn mapping and the
    empty-response guard — is shared, because each of those was a place the surveyed
    codebases had drifted between call sites.
    """

    #: Importable module name of the vendor SDK. Loaded lazily, never at import time.
    SDK_MODULE: ClassVar[str] = ""
    #: Extra that installs :attr:`SDK_MODULE`, quoted back in the error message.
    EXTRA: ClassVar[str] = ""
    #: Stable identifier recorded in attestations and cost records.
    PROVIDER_NAME: ClassVar[str] = "base"
    #: Model served when the caller does not name one.
    DEFAULT_MODEL: ClassVar[str] = ""
    #: Model-id markers whose models reject ``temperature`` / ``top_p`` with a 400.
    MODEL_CONTROLLED_SAMPLING: ClassVar[tuple[str, ...]] = ()

    __slots__ = ("_client", "_spec")

    @classmethod
    def require(cls, obj: object, *what: str) -> Any:
        """Read an attribute that must exist, or raise. **Never a silent default.**

        Token counts were read with ``getattr(usage, "input_tokens", 0)``. The default
        is the problem: an SDK major that renames the field does not raise, it produces
        a completion recorded at **zero tokens and zero cost** — silently wrong
        financial data in a sealed attestation, reconciling against a bill that says
        otherwise.

        A vendor rename should break loudly on the first call in staging, which is what
        an upper version bound plus this gives you. ``what`` accepts several spellings
        so a deliberate rename can be accommodated in one place rather than by
        reintroducing a default.
        """
        for name in what:
            found = getattr(obj, name, None)
            if found is not None:
                return found
        raise ProviderError(
            f"{type(obj).__name__} has none of {list(what)}. The vendor SDK has changed "
            f"shape: defaulting this away would record the call at zero cost, so it is "
            f"refused instead. Pin the SDK, or add the new name to the lookup."
        )

    @classmethod
    def required_key(cls, mapping: Mapping[str, Any], *what: str) -> Any:
        """:meth:`require`, for the backends whose SDK answers with dictionaries."""
        for name in what:
            if mapping.get(name) is not None:
                return mapping[name]
        raise ProviderError(
            f"the response usage carries none of {list(what)}: {sorted(mapping)}. The "
            f"vendor API has changed shape, and defaulting this away would record the "
            f"call at zero cost."
        )

    def __init__(
        self,
        *,
        model_id: str | None = None,
        region: str = "unspecified",
        family: str | None = None,
        zero_retention: bool = False,
        supports_tools: bool = True,
        supports_json: bool = True,
        name: str | None = None,
        client: Any = None,
    ) -> None:
        """Construct a backend.

        ``region`` is not decoration — :meth:`ProviderRouter.select` filters on it
        *before* consulting a provider, so a mislabelled region is how an outage
        becomes a data-transfer breach. It has no default that could be wrong by
        accident; ``"unspecified"`` matches no residency constraint.

        ``client`` is injected for tests and for deployments that build their own
        authenticated SDK client. When it is ``None`` the SDK is loaded on first use.
        """
        resolved = model_id or self.DEFAULT_MODEL
        if not resolved:
            raise ConfigurationError(
                f"{type(self).__name__} requires a model_id: this backend ships no default"
            )
        self._spec = ProviderSpec(
            name=name or self.PROVIDER_NAME,
            model_id=resolved,
            family=self._resolve_family(resolved, family),
            region=region,
            zero_retention=zero_retention,
            supports_tools=supports_tools,
            supports_json=supports_json,
        )
        self._client = client

    def _resolve_family(self, model_id: str, declared: str | None) -> str:
        """The weights family, declared or recognised — never guessed.

        Refusing to guess is the point. An unrecognised model with an inferred family
        would silently decide whether cross-family judging is permitted, and that
        decision is one of the framework's independence guarantees.
        """
        if declared:
            return declared
        recognised = ModelFamilies.resolve(model_id)
        if recognised is None:
            raise ConfigurationError(
                f"cannot determine the weights family of model {model_id!r}. Pass "
                f"family='...' explicitly. It is not inferred, because cross-family "
                f"judging (ADR 0041) compares this value to decide whether a judge is "
                f"independent of what it is judging — a guess there is an "
                f"independence claim nobody made."
            )
        return recognised

    # ── The gateway's protocol ───────────────────────────────────────────────

    @property
    def spec(self) -> ProviderSpec:
        return self._spec

    def supports(self, feature: Feature) -> bool:
        """Answered from the spec, which is what the router filtered on.

        A backend that knows better than its own spec overrides this — but the two
        must not disagree silently, because the router selected on the spec and the
        gateway asks the provider.
        """
        return self._spec.supports(feature)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise NotImplementedError

    # ── SDK loading ──────────────────────────────────────────────────────────

    @property
    def client(self) -> Any:
        """The vendor client, built on first use."""
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        raise NotImplementedError

    def _sdk(self) -> Any:
        """Import the vendor SDK, or explain precisely how to install it."""
        try:
            return importlib.import_module(self.SDK_MODULE)
        except ImportError as exc:
            raise ProviderUnavailable(
                f"the {self.PROVIDER_NAME} backend needs the {self.SDK_MODULE!r} SDK, "
                f"which is not installed. Run: "
                f"pip install 'attest-control-plane[{self.EXTRA}]'"
            ) from exc

    # ── Request and response shaping ─────────────────────────────────────────

    def _model_controls_sampling(self) -> bool:
        """Whether this model rejects caller-supplied sampling parameters."""
        candidate = self._spec.model_id.lower()
        return any(marker in candidate for marker in self.MODEL_CONTROLLED_SAMPLING)

    def _turns(self, request: CompletionRequest) -> list[dict[str, str]]:
        """Map the request's flat transcript onto alternating roles.

        ``CompletionRequest.messages`` is a tuple of strings because the gateway
        hashes it for the prompt cache and the attestation. Even indices are the user,
        odd indices the assistant — an ordinary transcript.

        The final turn must be the user's. Every current frontier model rejects a
        trailing assistant turn outright, and a backend that quietly appended a filler
        turn would change the prompt that was hashed into the attestation.
        """
        if not request.messages:
            raise ProviderError(
                f"{self.PROVIDER_NAME}: a completion request needs at least one message"
            )
        if len(request.messages) % 2 == 0:
            raise ProviderError(
                f"{self.PROVIDER_NAME}: the transcript ends on an assistant turn "
                f"({len(request.messages)} messages). Providers reject a trailing "
                f"assistant turn, and appending a filler turn here would change the "
                f"prompt that was hashed into the attestation."
            )
        return [
            {"role": "user" if index % 2 == 0 else "assistant", "content": text}
            for index, text in enumerate(request.messages)
        ]

    def _respond(
        self,
        *,
        text: str,
        input_tokens: int,
        output_tokens: int,
        metadata: dict[str, str],
    ) -> CompletionResponse:
        """Build the response, refusing to return an empty one.

        Empty text with a non-refusal stop reason means the call was truncated,
        filtered or otherwise cut short. Returning it would put a blank answer into an
        attestation that claims a model produced it.
        """
        if not text.strip():
            stop = metadata.get("stop_reason", "unknown")
            raise ProviderError(
                f"{self.PROVIDER_NAME} returned no text for model "
                f"{self._spec.model_id!r} (stop_reason={stop!r}). An empty completion "
                f"is a failed call, not an answer, and must not be recorded as one."
            )
        if self._model_controls_sampling():
            metadata.setdefault("sampling", "model-controlled")
        return CompletionResponse(
            text=text,
            provider=self._spec.name,
            model_id=self._spec.model_id,
            family=self._spec.family,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            metadata=metadata,
        )


class ChatCompletionsProvider(BaseProvider):
    """Backends speaking the chat-completions wire shape.

    Several vendors serve that shape — it is a protocol, not a vendor — so the parsing
    lives once here and each backend supplies only its client construction. Nothing in
    this class imports or names a particular SDK.
    """

    def _build_client(self) -> Any:
        raise NotImplementedError

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        payload: dict[str, Any] = {
            "model": self._spec.model_id,
            "messages": self._turns(request),
            "max_completion_tokens": request.max_tokens,
        }
        if not self._model_controls_sampling():
            payload["temperature"] = request.temperature
        if request.seed is not None:
            payload["seed"] = request.seed

        completion = self.client.chat.completions.create(**payload)
        choice = completion.choices[0]
        finish = str(getattr(choice, "finish_reason", "") or "")
        if finish == "content_filter":
            raise ProviderRefused(
                f"{self._spec.name} filtered the request for model "
                f"{self._spec.model_id!r}. Retrying the same request on the same model "
                f"will filter it again; route to a different family instead.",
                provider=self._spec.name,
                model_id=self._spec.model_id,
                category="content_filter",
            )

        usage = getattr(completion, "usage", None)
        metadata = {"stop_reason": finish}
        response_id = getattr(completion, "id", None)
        if response_id:
            metadata["response_id"] = str(response_id)
        return self._respond(
            text=str(getattr(choice.message, "content", "") or ""),
            input_tokens=int(self.require(usage, "prompt_tokens", "input_tokens")),
            output_tokens=int(self.require(usage, "completion_tokens", "output_tokens")),
            metadata=metadata,
        )
