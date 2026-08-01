# Domain catalogue

Domains the framework must serve. The six in this directory are worked in detail; this is
the wider landscape the design is answerable to.

## Tier 1 — liberty, life, and legal standing

The highest stakes. A wrong answer is irreversible or near-irreversible harm.

```
 ┌──────────────────────────┬──────────────────────────────────────────────┐
 │ DOMAIN                   │ WHAT MAKES IT HARD                           │
 ├──────────────────────────┼──────────────────────────────────────────────┤
 │ Clinical decision support│ Observation evidence; calibration; guideline │
 │                          │ versioning; clinician attestation            │
 │ Pharmacovigilance        │ Signal detection over sparse events; causality│
 │                          │ assessment; statutory reporting windows      │
 │ Clinical trials          │ Protocol deviation detection; blinding must   │
 │                          │ not be broken by the agent's own context     │
 │ Immigration & asylum     │ Country-of-origin evidence with contested     │
 │                          │ provenance; credibility assessment; appeal    │
 │ Criminal justice         │ Fairness is the dominant warrant; adverse     │
 │  (bail, parole, risk)    │ decisions must be contestable in court        │
 │ Child & adult protection │ Multi-source conflicting evidence; the cost   │
 │                          │ of a false negative and false positive differ │
 │                          │ by orders of magnitude and in both directions │
 │ Aviation / rail / nuclear│ Irreversible physical effects; hard latency   │
 │  safety and maintenance  │ budgets; the agent must never actuate         │
 └──────────────────────────┴──────────────────────────────────────────────┘
```

## Tier 2 — money, rights, and regulated outcomes

```
 ┌──────────────────────────┬──────────────────────────────────────────────┐
 │ Lending & mortgage       │ Fairness, proxy discrimination, counterfactual│
 │ Insurance u/w and claims │ Amount-scaled authority; wording versioning   │
 │ AML / sanctions / fraud  │ Volume; tipping-off; dual control             │
 │ Securities surveillance  │ Market-abuse detection; evidentiary standard  │
 │ Tax advisory and filing  │ Statutory deadlines; position disclosure      │
 │ Audit & assurance        │ Reconciliation; materiality; independence     │
 │ Financial reporting      │ Derivation trees thousands wide               │
 │ Pensions & investment    │ Suitability; a wrong recommendation compounds │
 │  advice                  │ for decades                                   │
 │ Employment & hiring      │ Protected characteristics; adverse action     │
 │ Benefits eligibility     │ Vulnerable claimants; appeal rights           │
 │ Public procurement       │ Auditability of award decisions               │
 │ Legal (contract, litig., │ Provision-level citation; privilege           │
 │  IP, compliance)         │ boundaries; conflict checks                   │
 └──────────────────────────┴──────────────────────────────────────────────┘
```

## Tier 3 — regulated operations

```
 ┌──────────────────────────┬──────────────────────────────────────────────┐
 │ Regulatory change impact │ The evidence corpus itself is the moving part │
 │ ESG / environmental      │ Assurance standards; greenwashing exposure    │
 │ Food safety & recall     │ Traceability; time-critical                   │
 │ Construction / building  │ Code compliance; life safety                  │
 │ Medical devices (QMS)    │ Design history; change control                │
 │ Energy grid operations   │ Real-time; physical consequence               │
 │ Maritime & customs       │ Multi-jurisdiction; sanctions overlap         │
 │ Cybersecurity IR         │ Time-critical; evidence chain of custody      │
 │ Education assessment     │ Fairness; appeal; candidate rights            │
 └──────────────────────────┴──────────────────────────────────────────────┘
```

## The pattern across all of them

Every domain above needs the same four core warrants and differs in exactly three ways:

```
   1. what counts as evidence        -> EvidenceKind + verifier
   2. what gates an action           -> ObligationSet
   3. what else can go wrong         -> extra WarrantKinds
```

That is the entire domain-profile protocol. If a domain needs a fourth axis, the design is
wrong — and finding such a domain is the most useful thing a reviewer could do with these
documents.

## Recurring warrant needs

```
   calibration        medical · risk scoring · triage · credit
   fairness           lending · hiring · justice · insurance pricing · benefits
   temporal_validity  regulatory · medical · insurance · tax
   contestability     any adverse decision about a person
   reconciliation     reporting · audit · AML filings · tax
   materiality        reporting · audit
   safety             clinical · industrial · aviation · energy
   chain_of_custody   forensics · cybersecurity IR · evidence handling
   independence       audit · assurance
   privilege          legal · regulatory investigations
```

`chain_of_custody`, `independence`, and `privilege` are not in any worked example. They are
listed to make the point that the warrant set will keep growing — which is the argument for
it being open.

## Low-stakes domains must also work

A framework usable **only** at the top end is a framework nobody adopts, because every
organisation in the tiers above also builds internal tooling, support bots, and ops
automation. If those must be built on something else, the framework is a second stack rather
than the stack.

```
   internal ops · customer support · sales ops · document triage
   knowledge search · summarisation · drafting assistance
```

These need the *same* plumbing — providers, failover, budget, injection defence, audit — and
almost none of the assurance ceremony.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  GenericProfile                                             │
   │    core warrants only                                       │
   │    epistemic: WARN, not BLOCK                               │
   │    no entailment judging                                    │
   │    obligations: capability + budget only                    │
   │    -> overhead approaches a bare gateway call               │
   └─────────────────────────────────────────────────────────────┘
```

**This is a load-bearing requirement, not a nicety.** It is also where the current design is
weakest — see [`../kernel/performance.md`](../kernel/performance.md) on assurance tiers. If the
minimum overhead of an `Attestation` is high, the framework is unusable for tier-3 and
low-stakes work, and it will lose the tier-1 work too because teams standardise on one stack.

## Domains the framework should NOT serve

Worth stating:

```
   real-time control loops     millisecond budgets; an LLM has no place
                               in the actuation path at all
   safety interlocks           must be deterministic and formally verified
   anything where a model      if the decision is fully specifiable, write
   adds no judgement           the rule — see composition.md, FunctionNode
```

The third is the most commonly ignored. A framework that makes agents easy encourages
agent-shaped solutions to problems that are not agent-shaped.
