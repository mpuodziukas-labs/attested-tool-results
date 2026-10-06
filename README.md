# attested-tool-results

Proves: an agent-side verifier accepts a tool result only when its signed receipt is valid, fresh, unseen, and tied to a call the agent actually issued. Verify in 60s: `bash run.sh`

An agent acts on tool output it cannot verify; a replayed, stale or spoofed tool reply steers it into a wrong action.

## The problem

An agent reads tool output as fact. Output can reach its context from places the tool never spoke: a reply captured earlier and sent again, a reply that sat too long, text injected into the transcript that looks like a tool answer, or bytes changed between the tool and the agent. If the agent acts on any of these it takes a wrong action with full confidence.

The fix is the same one a distributed system uses for a health probe. A probe reply counts only when it is fresh, says ok, and matches the identity of the node that was asked. A reply that fails any of the three is ignored, no matter how plausible it reads. Here a tool reply is the probe reply. It counts only when the signature says the runner produced it (identity), the timestamp is inside the time limit (fresh), the nonce was not used before and the result bytes match the signed hash (it is the same answer that was signed, once). Anything else is REJECTED with a named reason and never enters the agent's context.

## Run it (60s)

```
python3 -m pip install pytest
bash run.sh
```

`run.sh` honors `PY`, for example `PY=python3.12 bash run.sh`. Check one transcript, with the key in the environment (exit 0 all accepted, 1 any rejected, 2 unreadable or no key):

```
ATTEST_KEY=synthetic-demo-key-not-a-secret python3 -m attest verify tests/fixtures/replay.jsonl
```

printed:

```
ACCEPT line 2 call=c1 accepted
REJECT line 3 call=c1 replay
```

`bash run.sh` runs `python3 evaluate.py`, then `python3 -m pytest -q`, then `python3 mutants.py`. It exits 0 only if all three pass. `evaluate.py` printed:

```
| case | outcome as labeled |
|---|---|
| valid receipt accepted | 1/1 |
| forged signature | 1/1 |
| result swapped after signing | 1/1 |
| replayed receipt | 1/1 |
| stale receipt | 1/1 |
| ttl edge, age = ttl | 1/1 |
| ttl edge, age = ttl + 1 | 1/1 |
| spoofed output for a call never made | 1/1 |
| args mismatch | 1/1 |
| tool mismatch | 1/1 |
| missing receipt | 1/1 |
| clock skew | 1/1 |
| verifier error fails closed | 1/1 |
| garbage json | 1/1 |
```

`python3 mutants.py` printed:

```
control 2/2 test files pass unmodified
RED  signature: skip the HMAC check
RED  signature: accept an empty key
RED  call: accept a result for a call never made
RED  call: skip the tool name check
RED  args: skip the args hash check
RED  result: skip the result hash check
RED  ttl: no age limit, stale receipts pass
RED  ttl: edge off by one
RED  skew: future receipts pass
RED  skew: no tolerance at all
RED  replay: nonce reuse allowed
RED  receipt: a missing receipt is not checked
RED  parse: a garbage line is skipped
RED  fail open: a verifier error accepts
RED  empty: an empty transcript is accepted
RED  cli: exit 0 even when a result is rejected
RED  cli: an unreadable file exits 0
RED  cli: a missing key is not an error
RED  hostile: NaN timestamps pass
RED  hostile: duplicate JSON keys are accepted
RED  hostile: unknown fields on a result pass
RED  hostile: unknown fields in a receipt pass
RED  hostile: a call can be answered twice
RED  hostile: a receipt may predate its call
RED  hostile: a duplicate call id is kept silently
RED  hostile: lines split on unicode separators
RED  hostile: no nesting limit before json.loads
RED  hostile: nesting limit raised tenfold
RED  hostile: brackets inside strings are counted
RED  hostile: args hash ignores the depth limit
RED  hostile: floats allowed in args
RED  hostile: the CLI prints raw call ids
mutants killed 32/32
```

## How a receipt works

The tool runner signs each reply with HMAC-SHA256 over the canonical JSON of six fields: `call_id`, `tool`, `args_sha256`, `result_sha256`, `issued_at`, `nonce`. The receipt carries exactly those fields plus `sig`.

Two canonical forms are fixed, and a runner in another language must produce the same bytes. Test vectors with the expected hashes are in `tests/vectors/canonical.json`, and `tests/test_hostile.py` recomputes them with `hashlib` alone.

- Receipt MAC input: the exact output of Python `json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False)`, so ASCII only with `\uXXXX` escapes. `issued_at` is a finite number, and an integer is the safe choice.
- `args_sha256`: SHA-256 of the UTF-8 bytes of the call args in RFC 8785 (JCS) form, restricted to the subset `null`, `true`, `false`, strings, integers with absolute value at most 2^53-1, arrays and objects. No spaces, object keys sorted by UTF-16 code units, strings kept as UTF-8 with only `"`, `\`, and control characters escaped (`\b \t \n \f \r`, others as lowercase `\u00xx`). Floats are rejected as `malformed` because JCS number formatting is the part runners disagree on. Args nested deeper than 32 are `malformed`. Any line with brackets nested deeper than 64 (string contents skipped) is `malformed` before it is parsed, so the result does not depend on the Python version's recursion limit.

The transcript is one JSON object per line. `{"type": "call", "call_id", "tool", "args", "ts"}` is written by the agent harness when it issues a call. `{"type": "result", "ts", "result", "receipt"}` is the delivered reply, with `ts` the delivery time. The verifier checks, in this order:

1. The receipt exists, has the right field types, and carries no field beyond the six plus `sig`. The result event carries no field beyond `type`, `ts`, `result`, `receipt`. Both `ts` and `issued_at` are finite numbers.
2. The signature verifies under the key (an empty key rejects).
3. The `call_id` is a call the agent issued, with the same tool name and the same args hash.
4. The SHA-256 of the delivered result bytes equals `result_sha256`.
5. `issued_at` is not earlier than the call `ts` by more than 5 s (`issued_before_call`).
6. Age (delivery minus `issued_at`) is at most the TTL (300 s) and not more than 5 s negative.
7. The nonce has not been accepted before in this transcript. A rejected receipt does not use up its nonce.
8. The call has not been answered already (`already_answered`). One accepted result per `call_id`.

Any exception inside a check is a rejection (`verifier_error`). A line that is not valid JSON, has a NaN or Infinity constant, nests too deep or exceeds 4 MiB is a rejection (`malformed`), never skipped and never a traceback. A repeated key in one object is `duplicate_key`. A second call line with a known `call_id` is `duplicate_call`. Lines split on `\n` only. The CLI prints a call id verbatim only when it is 1 to 64 characters of `A-Za-z0-9_.:-`, else JSON-escaped. A transcript with no results to verify is a rejection (`empty_transcript`).

## What each planted case proves

Each case is a transcript in tests/fixtures, generated by fixtures_gen.py, with the labeled outcome per result line in cases.jsonl. The key is synthetic.

- valid receipt accepted: the control, one call and one matching reply.
- forged signature: signed with another key. `bad_signature`.
- result swapped after signing: the receipt covers one answer, another was delivered. `result_mismatch`.
- replayed receipt: the same receipt delivered twice. First is accepted, second is `replay`.
- stale receipt: delivered after the TTL. `stale`. The TTL edge is tested both sides: age 300 accepted, 301 rejected.
- spoofed output for a call never made: a validly signed receipt for a `call_id` the agent never issued. `unknown_call`.
- args mismatch, tool mismatch: the receipt is for a different argument set or a different tool than the agent asked for.
- missing receipt: `missing_receipt`.
- clock skew: a receipt dated in the future beyond 5 s. `clock_skew`.
- verifier error fails closed: a reply whose `result` is not text. `verifier_error`.
- garbage JSON: `malformed`.

## Mutants

Each defense is removed in a scratch copy and the tests must go RED. An unmodified control copy passes first. Each mutant has an 8 s limit, and a hang counts as killed. Every check above has at least one mutant, as does the fail-open path and the CLI exit codes.

## Honesty

This is a small deterministic verifier, not a product. The key, the transcripts and the results are synthetic and written for this repo. I did not run it against a real agent log. The claim is limited to the planted cases and the removed-defense mutants above. Time is read from the transcript delivery stamp, which makes runs repeatable and also means the stamp is trusted.

## Limitations

- A compromised tool runner that holds the key can sign lies. This proves integrity and freshness, not truth. A signed wrong answer is still accepted.
- The agent harness must write the call events and hold the verify key. If the agent can write its own call or result events, it can forge both.
- One shared key means anyone who can verify can also sign. Real use wants a per-runner key or an asymmetric signature.
- Replay memory lasts one transcript. A receipt replayed into a different session is stopped only by the TTL and by the rule that it cannot predate its call. The MAC carries no session id, so with predictable call ids (`c1`) a receipt from another session issued after the call still fits. Use unpredictable call ids to close this.
- Delivery time comes from the transcript. A forged delivery stamp can make an old receipt look fresh.
- It checks a recorded transcript. It does not stop an agent in flight, and it does not read what the result says.

## Hostile review 2026-10-04

An outside review (RED-RUN-REVIEW.txt) found 10 defects: 1 high, 9 medium, plus 3 passes. 10 of 10 fixed, each with a test in `tests/test_hostile.py`. Run against the pre-fix code (commit 92c49a7), that file gave 22 failed, 2 passed (RED-RUN-HOSTILE.txt), and it passes after the fix. The file holds 24 tests: the 21 from the review plus 3 added for the nesting limit. The mutants went from 18 to 32, all killed.
- A1 high: a NaN delivery time made both age checks false, so an old receipt never expired. Timestamps must now be finite numbers, and NaN and Infinity are refused at parse.
- A2: the CLI printed an unsigned call id raw, so a newline in it forged a verdict line. Ids are escaped.
- A3: `splitlines` cut transcripts at U+2028 and U+0085 inside strings. Lines split on `\n` only.
- A4: deeply nested JSON crashed with a traceback. Now a named `malformed` line, with depth and size limits.
- A5: a duplicate key let two parsers read different results. Now `duplicate_key`.
- A6: an unsigned sibling field rode along with a valid receipt. Exact field sets, else `unknown_field`.
- A7: one call could be answered twice. The second answer is `already_answered`.
- A8: a receipt issued before its call was accepted. Now `issued_before_call`. The session binding limit is stated under Limitations.
- A9: an injected earlier call line silently won. A repeated call id is `duplicate_call`.
- A10: "sorted keys, no spaces" hashes differently under RFC 8785. The args form is now JCS for a stated subset, with vectors.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py`, `python -m pytest -q` and `python mutants.py` on push and pull request.

## License

MIT, see LICENSE.
