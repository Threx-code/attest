# Decisions

Architecture decision records. What was chosen, what was rejected, and why.

## Settled

```
 ┌──────┬──────────────────────────────────┬──────────────────────────────┐
 │ ADR  │ DECISION                         │ DRIVER                       │
 ├──────┼──────────────────────────────────┼──────────────────────────────┤
 │ 0001 │ Warrant kinds are an open set,   │ a closed enum means adding a │
 │      │ not an enum                      │ domain edits the framework   │
 │ 0002 │ Evidence is a protocol with      │ lab values and computations  │
 │      │ pluggable verification, not a    │ have no verbatim quote       │
 │      │ document Citation                │                              │
 │ 0003 │ Authority is an obligation set,  │ cooling-off, dual control,   │
 │      │ not an autonomy ladder           │ deadlines are not rungs      │
 │ 0004 │ Storage is a port; the framework │ four surveyed AgentRun       │
 │      │ mandates no table                │ tables had diverged          │
 │ 0005 │ HOLD_FOR_APPROVAL is a verdict,  │ side-channel HITL lets call  │
 │      │ not an exception                 │ sites silently drop actions  │
 │ 0006 │ Domain profiles are plugins;     │ the open-world requirement   │
 │      │ the framework ships none         │                              │
 │ 0007 │ Config holds values; profiles    │ a `domain:` enum in config   │
 │      │ hold behaviour                   │ closes the world             │
 │ 0008 │ Python floor 3.12                │ serves all surveyed hosts    │
 │      │ SUPERSEDED BY 0036               │                              │
 │ 0009 │ One package, optional extras     │ shared overlap written once  │
 │ 0010 │ Guards fail closed, always       │ `except: return True` found  │
 │      │                                  │ in surveyed guard code       │
 │ 0016 │ Authorization grants bind effects│ TOCTOU between discharge and │
 │      │ to an action hash + nonce        │ effect                       │
 │ 0017 │ Effects have a lifecycle with a  │ payment commits, process     │
 │      │ terminal UNKNOWN state           │ crashes, no audit event      │
 │ 0018 │ Runs are SEALED: event count +   │ hash chains prove integrity, │
 │      │ dense sequence, sealer separate  │ not completeness             │
 │      │ from application code            │                              │
 │      │ AMENDED BY 0034                  │                              │
 │ 0019 │ verify_historical() is distinct  │ a June expiry does not       │
 │      │ from verify_current()            │ invalidate a January decision│
 │ 0020 │ Determinism is over a captured   │ capability/budget checks read│
 │      │ ExecutionContext, not absolute   │ external state               │
 │ 0021 │ COMPLETENESS is a first-class    │ every warrant validates what │
 │      │ warrant, scoped to a declared    │ WAS used; none asks what was │
 │      │ corpus and query plan            │ missed                       │
 │ 0022 │ Source authority is separate     │ a quote verifies against any │
 │      │ from content integrity           │ uploaded PDF                 │
 │ 0023 │ Profile conflicts classify as    │ retention 30 vs 90 days has  │
 │      │ STRICTER/COMPATIBLE/CONDITIONAL/ │ no scalar ordering           │
 │      │ CONTRADICTORY; no silent pick    │                              │
 │ 0024 │ Instruction memory forbidden by  │ persistent prompt injection  │
 │      │ default; facts carry provenance  │ across runs                  │
 │ 0025 │ Positioned as a control plane    │ the agent is one producer of │
 │      │ for governed AI actions          │ proposed actions, not the    │
 │      │                                  │ centre of the system         │
 │ 0011 │ Entailment defaults to NONE;     │ a default model call per     │
 │      │ profiles opt UP by materiality   │ claim makes it uneconomical  │
 │      │ Judges are cross-family          │ same-family judges fail in   │
 │      │                                  │ correlated ways              │
 │ 0014 │ Profiles are Python protocols;   │ obligation logic is          │
 │      │ YAML only for the data parts     │ conditional                  │
 │ 0015 │ Conformance + testing ship in v1 │ domains cannot be written    │
 │      │ eval/redteam harness in v1;      │ without them; bootstrap      │
 │      │ export/replay in v1.1            │ ordering was backwards       │
 │ 0027 │ Assurance TIERS: thin/std/full/  │ a framework usable only at   │
 │      │ max, with CI-enforced budgets    │ the top end is a second stack│
 │ 0028 │ Evidence persistence by          │ resolves small-vs-self-      │
 │      │ MATERIALITY: reference/digest/   │ verifying as a per-decision  │
 │      │ embedded                         │ choice, not a global one     │
 │ 0029 │ Streaming is two-phase and       │ verify-then-release excludes │
 │      │ FORBIDDEN by default             │ every interactive surface    │
 │ 0030 │ Counterfactuals computed over    │ a model-generated            │
 │      │ deterministic logic only; if     │ explanation is a plausible   │
 │      │ none exists, no automation       │ story, not a cause           │
 │ 0031 │ Refusal = we decided;            │ an inconsistent boundary is  │
 │      │ Exception = we cannot decide     │ a safety problem             │
 │ 0012 │ Signing is a pluggable Signer    │ offline evidence needs a     │
 │      │ port. KMS default, HSM optional, │ signature; key custody is a  │
 │      │ unsigned permitted for THIN tier │ deployment choice, not ours  │
 │ 0013 │ Sync core; async gateway later   │ all surveyed hosts are sync  │
 │      │ behind the same port             │ Django; dual APIs forever is │
 │      │                                  │ the larger cost              │
 │ 0026 │ External witness: Merkle         │ a host controlling its own DB│
 │      │ checkpoints + inclusion/         │ can rewrite a consistent     │
 │      │ consistency proofs + receipts.   │ history; self-certification  │
 │      │ Tiered NONE/TIMESTAMPED/LOGGED/  │ cannot detect it             │
 │      │ ANCHORED, domain-selected        │                              │
 │ 0032 │ The 25-attack threat model is    │ conformance proves well-     │
 │      │ the acceptance gate before any   │ formedness, not that the     │
 │      │ irreversible production action   │ kernel holds under attack    │
 ├──────┼──────────────────────────────────┼──────────────────────────────┤
 │ 0033 │ Verdict has SIX members, not     │ execution.md and errors.md   │
 │      │ four: + UNKNOWN, INCOMPLETE      │ both described reachable     │
 │      │                                  │ outcomes absent from the     │
 │      │                                  │ "closed" four-member enum,   │
 │      │                                  │ defeating exhaustive match   │
 │ 0034 │ Dense sequence and the hash      │ insert-time assignment +     │
 │      │ chain are assigned at SEAL time  │ end-of-run batching ordered  │
 │      │ over the canonical topological   │ effect events BEFORE the     │
 │      │ order, not at insert time        │ evidence that preceded them  │
 │      │ (amends 0018)                    │                              │
 │ 0035 │ Warrants carry EVALUATED/PENDING/│ deferred assurance returned  │
 │      │ UNEVALUATABLE; is_final derived; │ ALLOW with unevaluated       │
 │      │ export() refuses a non-final     │ warrants and no way for a    │
 │      │ attestation                      │ consumer to tell             │
 │ 0036 │ Python floor 3.11                │ nothing in the design needs  │
 │      │ (supersedes 0008)                │ 3.12; 3.11 covers Debian 12  │
 │      │                                  │ and RHEL 9, which regulated  │
 │      │                                  │ adopters actually run        │
 │ 0037 │ One replay vocabulary:           │ STRICT/PINNED/CURRENT ran in │
 │      │ HISTORICAL/VERIFY/BEHAVIOURAL.   │ parallel with it; STRICT was │
 │      │ Policy-as-at is a parameter      │ ambiguous between two modes  │
 │ 0038 │ ExecutionContext carries all     │ versioning.md required nine  │
 │      │ reconstruction axes and is       │ fields the documented        │
 │      │ hashed as one unit; Attestation  │ Attestation could not carry; │
 │      │ embeds it                        │ nine loose fields can drift  │
 │ 0039 │ A training run IS an Action;     │ an earlier reading assumed a │
 │      │ the grant binds the DATASET ROOT │ parallel lifecycle. Training │
 │      │ alongside model and hyper-       │ has args, cost, an artifact  │
 │      │ parameters                       │ and is irreversible - it     │
 │      │                                  │ fits the existing model      │
 │ 0042 │ Behaviour lives on CLASSES; no    │ the capability layer grew a   │
 │      │ module-level functions in the     │ mix of engine classes and     │
 │      │ package. Engines hold their       │ loose functions doing the same│
 │      │ collaborators; namespaces hold    │ job, which reads as arbitrary │
 │      │ shipped vocabulary; value objects │ and cannot be injected or     │
 │      │ own their own methods.            │ swapped. CI-enforced.         │
 │ 0041 │ Cross-family judging compares the │ Groq/Bedrock/Vertex all serve │
 │      │ MODEL family, not the provider    │ Llama; a provider check accepts│
 │      │                                   │ a Llama judge for a Llama     │
 │      │                                   │ generator, which measures     │
 │      │                                   │ consistency, not correctness  │
 │ 0040 │ Datasets are COMMITTED by sorted │ evidence trees are bounded   │
 │      │ Merkle root, never embedded.     │ at ~8KB; a training set has  │
 │      │ Sorting buys non-inclusion       │ 10^6-10^9 leaves. 10^9 =     │
 │      │ proofs. Erasure yields a tracked │ a 30-hash proof, ~1KB.       │
 │      │ ErasureImpact, NOT unlearning    │ Unlearning is not solvable   │
 └──────┴──────────────────────────────────┴──────────────────────────────┘
```

## Open

None. Every architectural decision is settled. Four residual risks are named and accepted
rather than deferred — see `assurance/threat-model.md`, "The four weakest links", and the
limit stated in `capabilities/witness.md`.

> **Maintenance rule.** A document that says a decision is "open" or "not yet settled" while
> this section says `Open: None` is a defect. CI greps for that contradiction and fails the
> build — the doc set must not disagree with itself about what has been decided.

## Format

One file per ADR, once written up:

```
   NNNN-short-title.md
     Status      proposed · accepted · superseded by NNNN
     Context     what forced the decision
     Decision    what was chosen
     Consequences what this costs, including what it makes harder
     Rejected    the alternatives, and why not
```

The `Rejected` section is the one that pays off later — most ADR value is stopping a
settled question from being reopened every six months.
