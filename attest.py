"""Accept a tool result only when its signed receipt is valid, fresh, unseen and matches a call the agent made.
Anything else is REJECTED with a named reason. Fail closed: errors reject."""
import hashlib, hmac, json, os, sys

FIELDS = ("call_id", "tool", "args_sha256", "result_sha256", "issued_at", "nonce")
TEXT = ("call_id", "tool", "args_sha256", "result_sha256", "nonce", "sig")


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _check(e, calls, seen, key, ttl, skew):
    r = e.get("receipt")
    if not isinstance(r, dict):
        return "missing_receipt"
    if not all(isinstance(r.get(k), str) for k in TEXT):
        return "malformed"
    if type(r.get("issued_at")) not in (int, float):
        return "malformed"
    if not key:
        return "no_key"
    want = hmac.new(key.encode(), canon({k: r[k] for k in FIELDS}).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, r["sig"]):
        return "bad_signature"
    call = calls.get(r["call_id"])
    if call is None:
        return "unknown_call"
    if call["tool"] != r["tool"]:
        return "tool_mismatch"
    if call["args_sha256"] != r["args_sha256"]:
        return "args_mismatch"
    if sha(e["result"]) != r["result_sha256"]:
        return "result_mismatch"
    age = e["ts"] - r["issued_at"]
    if age < -skew:
        return "clock_skew"
    if age > ttl:
        return "stale"
    if r["nonce"] in seen:
        return "replay"
    seen.add(r["nonce"])
    return None


def verify(lines, key, ttl=300, skew=5):
    """One dict per result event or bad line: {line, call_id, verdict, reason}."""
    out, calls, seen = [], {}, set()
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            e = json.loads(raw)
            kind = e["type"]
        except (ValueError, KeyError, TypeError):
            out.append({"line": n, "call_id": "?", "verdict": "REJECT", "reason": "malformed"})
            continue
        if kind == "call":
            try:
                calls.setdefault(e["call_id"], {"tool": e["tool"], "args_sha256": sha(canon(e["args"]))})
            except (KeyError, TypeError):
                out.append({"line": n, "call_id": "?", "verdict": "REJECT", "reason": "malformed"})
        elif kind == "result":
            try:
                reason = _check(e, calls, seen, key, ttl, skew)
            except Exception:
                reason = "verifier_error"
            rc = e.get("receipt")
            cid = rc.get("call_id", "?") if isinstance(rc, dict) else "?"
            out.append({"line": n, "call_id": cid if isinstance(cid, str) else "?",
                        "verdict": "ACCEPT" if reason is None else "REJECT", "reason": reason or "accepted"})
        else:
            out.append({"line": n, "call_id": "?", "verdict": "REJECT", "reason": "malformed"})
    return out or [{"line": 0, "call_id": "?", "verdict": "REJECT", "reason": "empty_transcript"}]


def main(argv=None, env=None):
    argv = sys.argv[1:] if argv is None else argv
    key = (os.environ if env is None else env).get("ATTEST_KEY", "")
    if len(argv) != 2 or argv[0] != "verify" or not key:
        print("usage: ATTEST_KEY=<key> python3 -m attest verify <transcript.jsonl>")
        return 2
    try:
        with open(argv[1], encoding="utf-8") as f:
            res = verify(f.read().splitlines(), key)
    except (OSError, UnicodeError) as e:
        print(f"REJECT cannot read transcript: {type(e).__name__}")
        return 2
    for r in res:
        print(f"{r['verdict']} line {r['line']} call={r['call_id']} {r['reason']}")
    return 1 if any(r["verdict"] == "REJECT" for r in res) else 0


if __name__ == "__main__":
    sys.exit(main())
