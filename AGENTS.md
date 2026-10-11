# Verifying this repository

Purpose: demonstrates an agent-side verifier that accepts a tool result only when its signed receipt is valid, fresh, unseen and tied to a call the agent issued for teams subject to model-risk, audit or change-control review.

Verify: `bash run.sh`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `mutants killed 32/32`

Scope: synthetic data, fixed seed, offline, under 60 seconds.

Limitations: Proves integrity and freshness, not truth: a compromised runner holding the key can sign lies. The harness must write call events and hold the verify key. One shared key means any verifier can also sign. Replay memory lasts one transcript. It checks a recorded transcript and does not stop an agent in flight.

Anything else = not verified.
