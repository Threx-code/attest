"""Provider backends — mostly the failure paths, because those are the dangerous ones.

A happy-path completion is easy to get right and easy to notice when it breaks. What
gets shipped broken is the refusal that comes back as an empty string, the truncated
response recorded as an answer, and the sampling parameter that 400s the moment the
deployment upgrades a model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import pytest

from attest.adapters.providers import (
    AnthropicProvider,
    BedrockProvider,
    ClaudeModels,
    DeterministicProvider,
    GeminiProvider,
    GroqProvider,
    OpenAIProvider,
    ProviderError,
    ProviderRefused,
    ProviderUnavailable,
    VertexAnthropicProvider,
)
from attest.capabilities.gateway import CompletionRequest, LLMProvider, ProviderRouter
from attest.kernel.errors import ConfigurationError

pytestmark = pytest.mark.unit

# ── Stand-ins for the vendor SDKs ────────────────────────────────────────────
#
# No test here touches the network, and none needs an SDK installed. A provider
# suite that only runs where credentials exist is a suite that gets skipped, and a
# skipped suite proves nothing about the failure paths — the refusal, the empty
# response, the ceiling — which are the ones that matter. The fakes mimic the
# *shapes* the backends read, using plain objects rather than the vendors' models,
# so a failure points at our parsing rather than at a library upgrade.


@dataclass
class Block:
    type: str
    text: str = ""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class StopDetails:
    category: str = ""


@dataclass
class Message:
    """The shape ``client.messages.create`` returns."""

    content: list[Block] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = "end_turn"
    stop_details: StopDetails | None = None
    id: str = "msg_1"
    model: str = ""


class _Stream:
    def __init__(self, message: Message) -> None:
        self._message = message

    def __enter__(self) -> _Stream:
        return self

    def __exit__(self, *exc: object) -> Literal[False]:
        return False

    def get_final_message(self) -> Message:
        return self._message


class FakeMessages:
    def __init__(self, message: Message) -> None:
        self.message = message
        self.calls: list[dict[str, Any]] = []
        self.streamed = False

    def create(self, **kwargs: Any) -> Message:
        self.calls.append(kwargs)
        return self.message

    def stream(self, **kwargs: Any) -> _Stream:
        self.calls.append(kwargs)
        self.streamed = True
        return _Stream(self.message)


class FakeAnthropicClient:
    """Stands in for ``anthropic.Anthropic()``."""

    def __init__(self, message: Message | None = None) -> None:
        self.messages = FakeMessages(message or Message([Block("text", "hello")], Usage(11, 7)))


@dataclass
class ChatMessage:
    content: str | None = "hello"


@dataclass
class Choice:
    message: ChatMessage = field(default_factory=ChatMessage)
    finish_reason: str = "stop"


@dataclass
class Completion:
    choices: list[Choice] = field(default_factory=lambda: [Choice()])
    usage: Usage = field(default_factory=lambda: Usage(prompt_tokens=5, completion_tokens=3))
    id: str = "cmpl_1"


class _Completions:
    def __init__(self, completion: Completion) -> None:
        self.completion = completion
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Completion:
        self.calls.append(kwargs)
        return self.completion


class _Chat:
    def __init__(self, completion: Completion) -> None:
        self.completions = _Completions(completion)


class FakeChatClient:
    """Stands in for any client speaking the chat-completions shape."""

    def __init__(self, completion: Completion | None = None) -> None:
        self.chat = _Chat(completion or Completion())

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.chat.completions.calls


class FakeBedrockClient:
    """Stands in for ``boto3.client("bedrock-runtime")``."""

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response or {
            "output": {"message": {"content": [{"text": "hello"}]}},
            "usage": {"inputTokens": 9, "outputTokens": 4},
            "stopReason": "end_turn",
        }
        self.calls: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


def request_for(
    *messages: str, max_tokens: int = 512, temperature: float = 0.0
) -> CompletionRequest:
    return CompletionRequest.for_messages(
        messages or ("hello",), max_tokens=max_tokens, temperature=temperature
    )


@dataclass
class BlockReason:
    name: str = "SAFETY"

    def __str__(self) -> str:
        return f"BlockedReason.{self.name}"


@dataclass
class PromptFeedback:
    block_reason: BlockReason | None = None


@dataclass
class GeminiUsage:
    prompt_token_count: int = 12
    candidates_token_count: int = 5
    cached_content_token_count: int = 0
    thoughts_token_count: int = 0


@dataclass
class GeminiCandidate:
    finish_reason: str = "FinishReason.STOP"


@dataclass
class GeminiResponse:
    text: str = "hello"
    candidates: list[GeminiCandidate] = field(default_factory=lambda: [GeminiCandidate()])
    usage_metadata: GeminiUsage = field(default_factory=GeminiUsage)
    prompt_feedback: PromptFeedback | None = None


class _Models:
    def __init__(self, response: GeminiResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> GeminiResponse:
        self.calls.append(kwargs)
        return self.response


class FakeGeminiClient:
    """Stands in for ``google.genai.Client()``."""

    def __init__(self, response: GeminiResponse | None = None) -> None:
        self.models = _Models(response or GeminiResponse())

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.models.calls


class FakeGenaiTypes:
    """Stands in for ``google.genai.types`` — records what the backend built."""

    class Content:
        def __init__(self, role: str, parts: list[Any]) -> None:
            self.role = role
            self.parts = parts

    class Part:
        def __init__(self, text: str) -> None:
            self.text = text

        @classmethod
        def from_text(cls, *, text: str) -> FakeGenaiTypes.Part:
            return cls(text)

    class GenerateContentConfig:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs


# ── The protocol, and the router that consumes it ────────────────────────────


@pytest.mark.parametrize(
    "provider",
    [
        DeterministicProvider(),
        AnthropicProvider(client=FakeAnthropicClient()),
        OpenAIProvider(client=FakeChatClient()),
        GroqProvider(client=FakeChatClient()),
        GeminiProvider(client=FakeGeminiClient()),
        BedrockProvider(model_id="anthropic.claude-opus-5", region="eu-west-2", client=object()),
        VertexAnthropicProvider(project_id="p", region="europe-west1", client=object()),
    ],
)
def test_every_backend_satisfies_the_gateway_protocol(provider: LLMProvider) -> None:
    assert isinstance(provider, LLMProvider)


def test_the_router_filters_a_backend_by_the_region_it_declares() -> None:
    """Residency is filtered before the provider is consulted, not after."""
    inside = AnthropicProvider(region="eu-west-2", client=FakeAnthropicClient())
    outside = AnthropicProvider(region="us-east-1", client=FakeAnthropicClient())
    router = ProviderRouter(permitted_regions=frozenset({"eu-west-2"}))
    selected = router.select([inside.spec, outside.spec])
    assert [spec.region for spec in selected] == ["eu-west-2"]


# ── Family resolution at construction ────────────────────────────────────────


def test_an_unrecognised_model_must_declare_its_family() -> None:
    with pytest.raises(ConfigurationError, match="family="):
        AnthropicProvider(model_id="acme-frontier-9")


def test_a_declared_family_is_taken_as_given() -> None:
    provider = AnthropicProvider(model_id="acme-frontier-9", family="acme", client=object())
    assert provider.spec.family == "acme"


def test_groq_reports_the_weights_family_not_the_vendor() -> None:
    """The whole reason Groq is worth adding, and the trap in adding it."""
    provider = GroqProvider(client=FakeChatClient())
    assert provider.spec.name == "groq"
    assert provider.spec.family == "llama"


# ── The Claude catalogue ─────────────────────────────────────────────────────


def test_the_catalogue_covers_the_whole_shipped_line() -> None:
    for model_id in (
        ClaudeModels.OPUS_5,
        ClaudeModels.OPUS_4_8,
        ClaudeModels.OPUS_4_7,
        ClaudeModels.OPUS_4_6,
        ClaudeModels.SONNET_5,
        ClaudeModels.SONNET_4_6,
        ClaudeModels.HAIKU_4_5,
        ClaudeModels.FABLE_5,
        ClaudeModels.MYTHOS_5,
    ):
        assert ClaudeModels.get(model_id) is not None, model_id


def test_haiku_carries_a_lower_output_ceiling_than_the_opus_line() -> None:
    """The case a substring rule gets wrong, and the reason there is a catalogue."""
    haiku = ClaudeModels.CATALOGUE[ClaudeModels.HAIKU_4_5]
    opus = ClaudeModels.CATALOGUE[ClaudeModels.OPUS_5]
    assert haiku.max_output_tokens == 64_000
    assert haiku.context_window < opus.context_window
    assert opus.max_output_tokens == 128_000


def test_a_request_above_the_model_ceiling_is_refused_before_the_call() -> None:
    client = FakeAnthropicClient()
    provider = AnthropicProvider(model_id=ClaudeModels.HAIKU_4_5, client=client)
    with pytest.raises(ProviderError, match="caps output"):
        provider.complete(request_for(max_tokens=128_000))
    assert client.messages.calls == [], "the ceiling must be checked before spending"


def test_sampling_is_withheld_from_models_that_reject_it() -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(model_id=ClaudeModels.OPUS_5, client=client).complete(request_for())
    assert "temperature" not in client.messages.calls[0]


def test_sampling_is_sent_to_models_that_accept_it() -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(model_id=ClaudeModels.HAIKU_4_5, client=client).complete(
        request_for(temperature=0.4)
    )
    assert client.messages.calls[0]["temperature"] == 0.4


def test_an_unknown_model_is_treated_as_controlling_its_own_sampling() -> None:
    """The cheap direction to be wrong in: a withheld knob, not a failed call."""
    client = FakeAnthropicClient()
    provider = AnthropicProvider(model_id="claude-next-9", client=client)
    response = provider.complete(request_for())
    assert "temperature" not in client.messages.calls[0]
    assert response.metadata["sampling"] == "model-controlled"


# ── Anthropic response handling ──────────────────────────────────────────────


def test_a_completion_records_tokens_and_the_family() -> None:
    client = FakeAnthropicClient(Message([Block("text", "the answer")], Usage(11, 7)))
    response = AnthropicProvider(client=client).complete(request_for())
    assert response.text == "the answer"
    assert (response.input_tokens, response.output_tokens) == (11, 7)
    assert response.family == "claude"


def test_thinking_blocks_are_not_mistaken_for_the_answer() -> None:
    client = FakeAnthropicClient(
        Message([Block("thinking", "deliberating"), Block("text", "final")], Usage(1, 1))
    )
    assert AnthropicProvider(client=client).complete(request_for()).text == "final"


def test_a_policy_refusal_raises_rather_than_returning_an_empty_answer() -> None:
    """HTTP 200 with no content is not an answer, and must not be recorded as one."""
    client = FakeAnthropicClient(
        Message([], Usage(), stop_reason="refusal", stop_details=StopDetails("cyber"))
    )
    with pytest.raises(ProviderRefused) as caught:
        AnthropicProvider(client=client).complete(request_for())
    assert caught.value.category == "cyber"
    assert caught.value.model_id == ClaudeModels.OPUS_5


def test_an_empty_completion_raises_rather_than_being_recorded() -> None:
    client = FakeAnthropicClient(Message([Block("text", "   ")], Usage(), stop_reason="max_tokens"))
    with pytest.raises(ProviderError, match="max_tokens"):
        AnthropicProvider(client=client).complete(request_for())


def test_a_server_side_fallback_is_recorded_as_a_distinct_fact() -> None:
    """A decision made by a different model is a materially different decision."""
    client = FakeAnthropicClient(
        Message([Block("text", "answered")], Usage(1, 1), model=ClaudeModels.OPUS_4_8)
    )
    response = AnthropicProvider(model_id=ClaudeModels.OPUS_5, client=client).complete(
        request_for()
    )
    assert response.metadata["served_by"] == ClaudeModels.OPUS_4_8


def test_a_large_output_request_is_streamed_rather_than_left_to_time_out() -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(client=client).complete(request_for(max_tokens=64_000))
    assert client.messages.streamed


def test_cached_input_tokens_are_carried_through() -> None:
    client = FakeAnthropicClient(
        Message([Block("text", "hi")], Usage(10, 2, cache_read_input_tokens=900))
    )
    response = AnthropicProvider(client=client).complete(request_for())
    assert response.metadata["cached_input_tokens"] == "900"


# ── Transcript mapping ───────────────────────────────────────────────────────


def test_the_transcript_alternates_roles_beginning_with_the_user() -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(client=client).complete(request_for("q1", "a1", "q2"))
    assert [turn["role"] for turn in client.messages.calls[0]["messages"]] == [
        "user",
        "assistant",
        "user",
    ]


def test_a_transcript_ending_on_an_assistant_turn_is_refused() -> None:
    """Filling in a turn here would change the prompt that was hashed."""
    with pytest.raises(ProviderError, match="assistant turn"):
        AnthropicProvider(client=FakeAnthropicClient()).complete(request_for("q1", "a1"))


def test_an_empty_transcript_is_refused() -> None:
    with pytest.raises(ProviderError, match="at least one message"):
        AnthropicProvider(client=FakeAnthropicClient()).complete(
            CompletionRequest.for_messages((), max_tokens=10)
        )


# ── Chat-completions backends ────────────────────────────────────────────────


def test_a_chat_completion_is_parsed_into_the_gateway_response() -> None:
    client = FakeChatClient()
    response = OpenAIProvider(model_id="gpt-4o", client=client).complete(request_for())
    assert response.text == "hello"
    assert (response.input_tokens, response.output_tokens) == (5, 3)
    assert client.calls[0]["max_completion_tokens"] == 512


def test_a_content_filter_is_a_refusal_not_a_retryable_failure() -> None:
    client = FakeChatClient(Completion([Choice(ChatMessage(""), finish_reason="content_filter")]))
    with pytest.raises(ProviderRefused) as caught:
        OpenAIProvider(model_id="gpt-4o", client=client).complete(request_for())
    assert caught.value.category == "content_filter"


def test_a_reasoning_model_is_not_sent_a_temperature() -> None:
    client = FakeChatClient()
    OpenAIProvider(model_id="gpt-5", client=client).complete(request_for(temperature=0.9))
    assert "temperature" not in client.calls[0]


def test_azure_is_a_parameter_and_renames_the_provider() -> None:
    """Same SDK, same wire shape — what differs is residency, which is already a field."""
    provider = OpenAIProvider(
        model_id="gpt-4o",
        azure_endpoint="https://acme.openai.azure.com",
        region="uksouth",
        client=FakeChatClient(),
    )
    assert provider.spec.name == "azure-openai"
    assert provider.complete(request_for()).provider == "azure-openai"


def test_an_azure_deployment_must_declare_its_region() -> None:
    with pytest.raises(ConfigurationError, match="region"):
        OpenAIProvider(model_id="gpt-4o", azure_endpoint="https://acme.openai.azure.com")


# ── Bedrock ──────────────────────────────────────────────────────────────────


def test_bedrock_converse_is_parsed_and_the_region_reaches_the_spec() -> None:
    client = FakeBedrockClient()
    provider = BedrockProvider(
        model_id="anthropic.claude-opus-5", region="eu-west-2", client=client
    )
    response = provider.complete(request_for())
    assert response.text == "hello"
    assert (response.input_tokens, response.output_tokens) == (9, 4)
    assert provider.spec.family == "claude"
    assert client.calls[0]["messages"] == [{"role": "user", "content": [{"text": "hello"}]}]


def test_a_bedrock_guardrail_is_a_refusal() -> None:
    client = FakeBedrockClient(
        {
            "output": {"message": {"content": []}},
            "usage": {"inputTokens": 1, "outputTokens": 0},
            "stopReason": "guardrail_intervened",
        }
    )
    provider = BedrockProvider(model_id="meta.llama3-3-70b", region="eu-west-2", client=client)
    with pytest.raises(ProviderRefused):
        provider.complete(request_for())


def test_bedrock_requires_an_explicit_region() -> None:
    with pytest.raises(ConfigurationError, match="region"):
        BedrockProvider(model_id="anthropic.claude-opus-5")


def test_vertex_requires_an_explicit_region() -> None:
    with pytest.raises(ConfigurationError, match="region"):
        VertexAnthropicProvider(project_id="p", client=object())


# ── SDK absence ──────────────────────────────────────────────────────────────


class _MissingSdkProvider(AnthropicProvider):
    SDK_MODULE = "attest_no_such_sdk"
    EXTRA = "anthropic"


def test_a_missing_sdk_names_the_extra_that_installs_it() -> None:
    """A bare ModuleNotFoundError six frames down makes an extra look like a bug."""
    with pytest.raises(ProviderUnavailable, match=r"attest-control-plane\[anthropic\]"):
        _MissingSdkProvider().complete(request_for())


# ── The dependency-free backend ──────────────────────────────────────────────


def test_the_deterministic_provider_is_stable_across_calls() -> None:
    """Replay of a run that used it reproduces byte-identical output."""
    provider = DeterministicProvider()
    first = provider.complete(request_for("a question"))
    second = provider.complete(request_for("a question"))
    assert first.text == second.text
    assert first.text != provider.complete(request_for("another question")).text


def test_the_deterministic_provider_says_what_it_is() -> None:
    response = DeterministicProvider().complete(request_for())
    assert response.metadata["synthetic"] == "true"
    assert response.text.startswith("[deterministic]")


def test_two_deterministic_providers_share_a_family_so_they_cannot_judge_each_other() -> None:
    """They are the same function; calling them independent would fake the check."""
    assert DeterministicProvider().spec.family == DeterministicProvider(prefix="x").spec.family


# ── Gemini ───────────────────────────────────────────────────────────────────


def gemini(
    monkeypatch: pytest.MonkeyPatch, response: GeminiResponse | None = None, **kwargs: Any
) -> GeminiProvider:
    provider = GeminiProvider(client=FakeGeminiClient(response), **kwargs)
    monkeypatch.setattr(GeminiProvider, "_types", lambda self: FakeGenaiTypes)
    return provider


def test_gemini_parses_a_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = gemini(monkeypatch)
    response = provider.complete(request_for())
    assert response.text == "hello"
    assert (response.input_tokens, response.output_tokens) == (12, 5)
    assert response.family == "gemini"


def test_gemini_names_the_model_turn_model_not_assistant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Passing 'assistant' through would drop the history and change the hashed prompt."""
    provider = gemini(monkeypatch)
    provider.complete(request_for("q1", "a1", "q2"))
    contents = provider.client.calls[0]["contents"]
    assert [turn.role for turn in contents] == ["user", "model", "user"]
    assert [turn.parts[0].text for turn in contents] == ["q1", "a1", "q2"]


def test_gemini_passes_the_output_ceiling_through(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = gemini(monkeypatch)
    provider.complete(request_for(max_tokens=2048))
    assert provider.client.calls[0]["config"].kwargs["max_output_tokens"] == 2048


def test_a_blocked_prompt_is_a_refusal_not_an_empty_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No candidate at all, so the SDK's .text is empty — with a reportable cause."""
    blocked = GeminiResponse(
        text="", candidates=[], prompt_feedback=PromptFeedback(BlockReason("SAFETY"))
    )
    provider = gemini(monkeypatch, blocked)
    with pytest.raises(ProviderRefused) as caught:
        provider.complete(request_for())
    assert caught.value.category == "safety"


def test_a_filtered_candidate_is_a_refusal_rather_than_partial_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    filtered = GeminiResponse(
        text="partial", candidates=[GeminiCandidate("FinishReason.PROHIBITED_CONTENT")]
    )
    provider = gemini(monkeypatch, filtered)
    with pytest.raises(ProviderRefused, match="PROHIBITED_CONTENT"):
        provider.complete(request_for())


def test_gemini_records_thinking_and_cached_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Thinking tokens are billed as output; a cost figure that omits them cannot reconcile."""
    response = GeminiResponse(
        usage_metadata=GeminiUsage(
            prompt_token_count=10,
            candidates_token_count=4,
            cached_content_token_count=900,
            thoughts_token_count=250,
        )
    )
    provider = gemini(monkeypatch, response)
    completed = provider.complete(request_for())
    assert completed.metadata["cached_input_tokens"] == "900"
    assert completed.metadata["thinking_tokens"] == "250"


def test_gemini_on_vertex_is_a_parameter_and_renames_the_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = gemini(monkeypatch, project="proj-1", region="europe-west1")
    assert provider.spec.name == "vertex-gemini"
    assert provider.complete(request_for()).provider == "vertex-gemini"


def test_gemini_on_vertex_requires_a_region() -> None:
    with pytest.raises(ConfigurationError, match="region"):
        GeminiProvider(project="proj-1", client=FakeGeminiClient())


def test_the_developer_api_needs_no_region() -> None:
    """It is not regional, and claiming a region it does not have would be a false label."""
    assert GeminiProvider(client=FakeGeminiClient()).spec.region == "unspecified"
