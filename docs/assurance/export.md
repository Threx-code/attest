# Evidence export

**A bundle a regulator can verify without our code.**

## The requirement

```
   If checking the bundle requires the framework,
   it is not evidence — it is a claim about evidence.
```

An export must be verifiable offline, by someone with no access to the system, no database,
and no network — using standard tools.

## Bundle layout

```
   bundle-01J8X4.../
     ├── attestation.json      the full record: verdict, warrants, cost
     ├── evidence/
     │     ├── manifest.json   every evidence item, kind, hash, validity
     │     ├── PW-2019.pdf     sources AS RETRIEVED at run time
     │     ├── record-8823.json
     │     └── calc-v2.1.json  computation inputs + output, pinned
     ├── chain.jsonl           the provenance events, in canonical order
     ├── seal.json             event_count, sequence range, head hash
     ├── prompts/
     │     └── fragments.json  every prompt fragment + hash
     ├── witness/              present when witness level > NONE
     │     ├── checkpoint.json      root, tree_size, timestamp, signature
     │     ├── inclusion_proof.json audit path for this leaf
     │     └── receipt.json         the promise issued at decision time
     ├── manifest.json         sha256 of every file above
     ├── signature.sig         detached signature over manifest.json
     └── VERIFY.md             how to check all of it by hand
```

The `witness/` directory is omitted at witness level `NONE` and present otherwise — see
[`../capabilities/witness.md`](../capabilities/witness.md). `VERIFY.md` is generated to match
the bundle it ships with, so its steps never reference a directory that is not there.

## Only final attestations export

`export()` **refuses a non-final attestation** — one where any warrant is still `PENDING`
because the profile deferred assurance
([`../kernel/performance.md`](../kernel/performance.md)).

An evidence bundle is what goes to a regulator. Producing one whose warrants had not yet been
evaluated would present an unverified result as a settled record, which is the failure this
framework exists to prevent. Deferred assurance must settle first. See ADR 0035.

## `VERIFY.md` is mandatory

It contains the actual commands, not a description of them:

```
   1. Recompute file hashes
        sha256sum -c manifest.json

   2. Verify the signature
        openssl dgst -sha256 -verify pubkey.pem \
                -signature signature.sig manifest.json

   3. Walk the provenance chain
        each event's `prev` must equal the previous event's `hash`;
        chain.jsonl line 1 has prev = ""

   4. Check the seal covers the whole chain
        seal.json `event_count` must equal the line count of chain.jsonl,
        `sequence_range` must be dense 1..event_count with no gaps, and
        `head_hash` must equal the last event's hash

   5. Spot-check a citation
        attestation.json -> warrants.epistemic.evidence[n]
        gives source file, offset, and the quoted text.
        Open the file at that offset; the text must match.

   --- the following steps appear only when witness/ is present ---

   6. Recompute the leaf hash
        sha256(attestation.json || seal.json), per witness/receipt.json

   7. Walk the inclusion proof
        fold the audit path in witness/inclusion_proof.json up to a root

   8. Compare that root to the INDEPENDENTLY published checkpoint
        obtain it from the third-party log, NOT from this bundle
```

Step 8 is the one that makes the bundle externally trustworthy rather than internally
consistent: the value it compares against comes from someone other than us. Step 4 is what
detects an omitted event — a chain can be internally valid and still be missing an event, so
linkage alone is not enough. See [`../capabilities/audit.md`](../capabilities/audit.md).

If a step needs our code, the bundle has failed its purpose.

## Sources are captured as retrieved

Not referenced — **embedded**. A bundle that links to a document is worthless the day that
document is edited or the URL rots.

```
   ┌──────────────────────────────────────────────────────────┐
   │  captures the state of the world at decision time,       │
   │  which is the only state that can justify the decision   │
   └──────────────────────────────────────────────────────────┘
```

This has a size consequence, and it is deliberate. Where sources are large, the bundle stores
the retrieved *extract* plus the full source hash, so the extract is verifiable against the
original if it still exists — and self-contained if it does not.

## Redaction for disclosure

The same run may need different bundles for different audiences.

```
   internal      everything
   regulator     everything, PII intact, under a legal basis
   subject       their own data; other subjects redacted
   litigation    scoped to the disclosure order
```

```python
bundle = attestation.export(profile=DisclosureProfile.SUBJECT, subject=subject_ref)
```

Redaction must not break verification. The manifest records which files were redacted and
carries the **original** hashes, so a verifier can confirm nothing else was altered while
accepting that redacted content will not match.

## When to export

```
   on challenge      a decision is disputed
   on schedule       sampled, to prove the pipeline works before it is needed
   on request        subject access / regulatory demand
   on incident       preserving state before anything is changed
```

The scheduled sample matters most. An export pipeline first exercised during a regulatory
demand is an export pipeline that will fail during a regulatory demand.

## Related

- [`../concepts/attestation.md`](../concepts/attestation.md) — `.export()`
- [`../capabilities/audit.md`](../capabilities/audit.md) — the chain and signing
- [`../capabilities/evidence.md`](../capabilities/evidence.md) — the evidence tree
