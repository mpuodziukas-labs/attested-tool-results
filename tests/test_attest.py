import pathlib, subprocess, sys
import pytest
from attest import verify
from fixtures_gen import KEY, FILES, lines, call, result, receipt, GOOD, OK

FIX = pathlib.Path(__file__).parent / "fixtures"
ROOT = pathlib.Path(__file__).parent.parent
K = KEY.decode()


def run(name, **kw):
    return verify((FIX / f"{name}.jsonl").read_text().splitlines(), K, **kw)


def reasons(name, **kw):
    return [(r["line"], r["reason"]) for r in run(name, **kw)]


def test_valid_receipt_is_accepted():
    assert reasons("valid") == [(2, "accepted")]
    assert run("valid")[0]["verdict"] == "ACCEPT"


def test_forged_signature_is_rejected():
    assert reasons("forged_signature") == [(2, "bad_signature")]


def test_result_swapped_after_signing_is_rejected():
    assert reasons("swapped_result") == [(2, "result_mismatch")]


def test_replayed_receipt_is_rejected_on_second_delivery():
    assert reasons("replay") == [(2, "accepted"), (3, "replay")]


def test_stale_receipt_is_rejected():
    assert reasons("stale") == [(2, "stale")]


def test_ttl_boundary_is_inclusive():
    assert reasons("ttl_edge_ok") == [(2, "accepted")]
    assert reasons("ttl_edge_over") == [(2, "stale")]


def test_ttl_is_a_parameter():
    assert reasons("valid", ttl=0) == [(2, "stale")]


def test_output_for_a_call_the_agent_never_made_is_rejected():
    assert reasons("spoofed_call") == [(2, "unknown_call")]


def test_args_mismatch_is_rejected():
    assert reasons("args_mismatch") == [(2, "args_mismatch")]


def test_tool_mismatch_is_rejected():
    assert reasons("tool_mismatch") == [(2, "tool_mismatch")]


def test_missing_receipt_is_rejected():
    assert reasons("missing_receipt") == [(2, "missing_receipt")]


def test_receipt_from_the_future_beyond_skew_is_rejected():
    assert reasons("clock_skew") == [(2, "clock_skew")]


def test_verifier_exception_fails_closed():
    assert reasons("result_not_text") == [(2, "verifier_error")]


def test_garbage_json_is_rejected_not_skipped():
    assert reasons("garbage_json") == [(2, "malformed")]


def test_empty_key_rejects_even_a_valid_receipt():
    out = verify((FIX / "valid.jsonl").read_text().splitlines(), "")
    assert [r["verdict"] for r in out] == ["REJECT"]


def test_empty_transcript_is_a_rejection():
    out = verify([], K)
    assert [r["verdict"] for r in out] == ["REJECT"] and out[0]["reason"] == "empty_transcript"


def test_calls_without_results_is_a_rejection():
    out = verify(lines([FILES["valid"][0]]), K)
    assert [r["reason"] for r in out] == ["empty_transcript"]


def test_a_rejected_receipt_does_not_burn_the_nonce():
    ev = [FILES["valid"][0], result("c1", "tampered", GOOD), result("c1", OK, GOOD, ts=1002)]
    assert [r["reason"] for r in verify(lines(ev), K)] == ["result_mismatch", "accepted"]


def cli(args, key=K):
    env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    if key is not None:
        env["ATTEST_KEY"] = key
    return subprocess.run([sys.executable, "-m", "attest", *args], cwd=ROOT, capture_output=True, text=True, env=env, timeout=20)


def test_cli_exits_0_when_all_accepted_and_prints_one_line_per_result():
    r = cli(["verify", "tests/fixtures/valid.jsonl"])
    assert r.returncode == 0 and r.stdout.strip().splitlines() == ["ACCEPT line 2 call=c1 accepted"]


def test_cli_exits_1_when_any_rejected():
    r = cli(["verify", "tests/fixtures/replay.jsonl"])
    assert r.returncode == 1
    assert r.stdout.strip().splitlines() == ["ACCEPT line 2 call=c1 accepted", "REJECT line 3 call=c1 replay"]


@pytest.mark.parametrize("name", sorted(FILES))
def test_cli_exit_matches_verdicts_on_every_fixture(name):
    want = 0 if all(r["verdict"] == "ACCEPT" for r in run(name)) else 1
    assert cli(["verify", f"tests/fixtures/{name}.jsonl"]).returncode == want


def test_cli_without_key_exits_2():
    assert cli(["verify", "tests/fixtures/valid.jsonl"], key=None).returncode == 2


def test_cli_unreadable_file_exits_2():
    assert cli(["verify", "tests/fixtures/nope.jsonl"]).returncode == 2


def test_receipt_signed_with_an_empty_key_is_not_accepted_under_an_empty_key():
    ev = [FILES["valid"][0], result("c1", OK, receipt("c1", OK, key=b""))]
    assert [r["reason"] for r in verify(lines(ev), "")] == ["no_key"]


def test_small_forward_clock_skew_is_tolerated():
    ev = [FILES["valid"][0], result("c1", OK, receipt("c1", OK, issued=1004))]
    assert [r["reason"] for r in verify(lines(ev), K)] == ["accepted"]
