"""Mutation check: remove each defense in a scratch copy, the matching tests must go RED.
A control copy must pass first. A mutant that hangs past 8 s counts as killed."""
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).parent
T = "tests/test_attest.py"
# (name, file, text to remove, text to put in, test file that must fail)
MUTANTS = [
    ("signature: skip the HMAC check", "attest.py", 'if not hmac.compare_digest(want, r["sig"]):', "if False:", T),
    ("signature: accept an empty key", "attest.py", "    if not key:", "    if False:", T),
    ("call: accept a result for a call never made", "attest.py", "if call is None:", "if False:", T),
    ("call: skip the tool name check", "attest.py", 'if call["tool"] != r["tool"]:', "if False:", T),
    ("args: skip the args hash check", "attest.py", 'if call["args_sha256"] != r["args_sha256"]:', "if False:", T),
    ("result: skip the result hash check", "attest.py", 'if sha(e["result"]) != r["result_sha256"]:', "if False:", T),
    ("ttl: no age limit, stale receipts pass", "attest.py", "if age > ttl:", "if False:", T),
    ("ttl: edge off by one", "attest.py", "if age > ttl:", "if age >= ttl:", T),
    ("skew: future receipts pass", "attest.py", "if age < -skew:", "if False:", T),
    ("skew: no tolerance at all", "attest.py", "if age < -skew:", "if age < 0:", T),
    ("replay: nonce reuse allowed", "attest.py", 'if r["nonce"] in seen:', "if False:", T),
    ("receipt: a missing receipt is not checked", "attest.py", "if not isinstance(r, dict):", "if False:", T),
    ("parse: a garbage line is skipped", "attest.py", '"reason": "malformed"})\n            continue',
     '"reason": "malformed"}) if 0 else None\n            continue', T),
    ("fail open: a verifier error accepts", "attest.py", 'reason = "verifier_error"', "reason = None", T),
    ("empty: an empty transcript is accepted", "attest.py", '"verdict": "REJECT", "reason": "empty_transcript"', '"verdict": "ACCEPT", "reason": "empty_transcript"', T),
    ("cli: exit 0 even when a result is rejected", "attest.py", 'return 1 if any(r["verdict"] == "REJECT" for r in res) else 0', "return 0", T),
    ("cli: an unreadable file exits 0", "attest.py", 'print(f"REJECT cannot read transcript: {type(e).__name__}")\n        return 2',
     'print(f"REJECT cannot read transcript: {type(e).__name__}")\n        return 0', T),
    ("cli: a missing key is not an error", "attest.py", 'argv[0] != "verify" or not key:', 'argv[0] != "verify":', T),
]


def pytest_rc(tree, test):
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                           cwd=tree, capture_output=True, timeout=8,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124                                      # a mutant that hangs the tests is caught
    return r.returncode


def fresh(tmp, name):
    dst = pathlib.Path(tmp) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dst


def main():
    killed = 0
    tests = sorted({m[4] for m in MUTANTS})
    with tempfile.TemporaryDirectory() as tmp:
        for t in tests:
            if pytest_rc(fresh(tmp, "control-" + pathlib.Path(t).stem), t) != 0:
                print(f"control FAIL {t}"); return 1
        print(f"control {len(tests)}/{len(tests)} test files pass unmodified")
        for i, (name, f, old, new, test) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1"); return 1
            (tree / f).write_text(src.replace(old, new))
            red = pytest_rc(tree, test) != 0
            killed += red
            print(f"{'RED ' if red else 'LIVE'} {name}")
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
