"""Accept a tool result only when its signed receipt is valid, fresh, unseen and matches a call the agent made.
Anything else is REJECTED with a named reason. Fail closed: errors reject."""
import hashlib, hmac, json, math, os, re, sys

FIELDS = ("call_id", "tool", "args_sha256", "result_sha256", "issued_at", "nonce")
TEXT = ("call_id", "tool", "args_sha256", "result_sha256", "nonce", "sig")
RECEIPT_KEYS = set(FIELDS) | {"sig"}
RESULT_KEYS = {"type", "ts", "result", "receipt"}
MAX_LINE = 4 << 20      # characters per transcript line
MAX_DEPTH = 32          # nesting depth of call args
MAX_PARSE_DEPTH = 64    # bracket nesting allowed in a raw line, checked before json.loads
MAX_INT = 2 ** 53 - 1   # largest integer allowed in args (I-JSON safe range)
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


class Dup(ValueError):
    pass


def canon(o):
    """MAC input: sorted keys, no spaces, ASCII escapes (exact Python json.dumps), no NaN/Infinity."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canon_args(o, depth=0):
    """Call args canonical form: RFC 8785 JCS restricted to null, bool, string, integer, array, object."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    if o is None or o is True or o is False:
        return json.dumps(o)
    if isinstance(o, str):
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, int):
        if abs(o) > MAX_INT:
            raise ValueError("integer out of range")
        return str(o)
    if isinstance(o, list):
        return "[" + ",".join(canon_args(v, depth + 1) for v in o) + "]"
    if isinstance(o, dict):
        ks = sorted(o, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon_args(o[k], depth + 1) for k in ks) + "}"
    raise ValueError("type not allowed in args")


def _check_depth(raw):
    """Linear scan: raise ValueError when [ and { nest deeper than MAX_PARSE_DEPTH. String contents are skipped."""
    depth, in_str, esc = 0, False, False
    for ch in raw:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_PARSE_DEPTH:
                raise ValueError("nesting too deep")
        elif ch in "]}":
            depth -= 1


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Dup(k)
        d[k] = v
    return d


def _const(name):
    raise ValueError("non-finite constant " + name)


def _num(x):
    return type(x) in (int, float) and math.isfinite(x)


def _check(e, calls, seen, answered, key, ttl, skew):
    r = e.get("receipt")
    if not isinstance(r, dict):
        return "missing_receipt"
    if not set(e) <= RESULT_KEYS:
        return "unknown_field"
    if not all(isinstance(r.get(k), str) for k in TEXT):
        return "malformed"
    if not _num(r.get("issued_at")) or not _num(e.get("ts")):
        return "malformed"
    if not set(r) <= RECEIPT_KEYS:
        return "unknown_field"
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
    if r["issued_at"] < call["ts"] - skew:
        return "issued_before_call"
    age = e["ts"] - r["issued_at"]
    if age < -skew:
        return "clock_skew"
    if age > ttl:
        return "stale"
    if r["nonce"] in seen:
        return "replay"
    if r["call_id"] in answered:
        return "already_answered"
    seen.add(r["nonce"])
    answered.add(r["call_id"])
    return None


def _bad(n, reason, cid="?"):
    return {"line": n, "call_id": cid, "verdict": "REJECT", "reason": reason}


def verify(lines, key, ttl=300, skew=5):
    """One dict per result event or bad line: {line, call_id, verdict, reason}."""
    out, calls, seen, answered = [], {}, set(), set()
    for n, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            if len(raw) > MAX_LINE:
                raise ValueError("line too long")
            _check_depth(raw)
            e = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_const)
            kind = e["type"]
        except Dup:
            out.append(_bad(n, "duplicate_key"))
            continue
        except (ValueError, KeyError, TypeError, RecursionError):
            out.append(_bad(n, "malformed"))
            continue
        if kind == "call":
            try:
                cid, tool, ts = e["call_id"], e["tool"], e["ts"]
                if not (isinstance(cid, str) and isinstance(tool, str) and _num(ts)):
                    raise TypeError("field type")
                entry = {"tool": tool, "args_sha256": sha(canon_args(e["args"])), "ts": ts}
            except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
                out.append(_bad(n, "malformed"))
                continue
            if cid in calls:
                out.append(_bad(n, "duplicate_call", cid))
            else:
                calls[cid] = entry
        elif kind == "result":
            try:
                reason = _check(e, calls, seen, answered, key, ttl, skew)
            except Exception:
                reason = "verifier_error"
            rc = e.get("receipt")
            cid = rc.get("call_id", "?") if isinstance(rc, dict) else "?"
            out.append({"line": n, "call_id": cid if isinstance(cid, str) else "?",
                        "verdict": "ACCEPT" if reason is None else "REJECT", "reason": reason or "accepted"})
        else:
            out.append(_bad(n, "malformed"))
    return out or [_bad(0, "empty_transcript")]


def _show(cid):
    return cid if cid == "?" or SAFE_ID.fullmatch(cid) else json.dumps(cid)


def main(argv=None, env=None):
    argv = sys.argv[1:] if argv is None else argv
    key = (os.environ if env is None else env).get("ATTEST_KEY", "")
    if len(argv) != 2 or argv[0] != "verify" or not key:
        print("usage: ATTEST_KEY=<key> python3 -m attest verify <transcript.jsonl>")
        return 2
    try:
        with open(argv[1], encoding="utf-8", newline="") as f:
            res = verify(f.read().split("\n"), key)
    except (OSError, UnicodeError) as e:
        print(f"REJECT cannot read transcript: {type(e).__name__}")
        return 2
    except Exception as e:
        print(f"REJECT verifier failure: {type(e).__name__}")
        return 1
    for r in res:
        print(f"{r['verdict']} line {r['line']} call={_show(r['call_id'])} {r['reason']}")
    return 1 if any(r["verdict"] == "REJECT" for r in res) else 0


if __name__ == "__main__":
    sys.exit(main())
