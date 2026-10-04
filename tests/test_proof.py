import pathlib
import evaluate, fixtures_gen, mutants

ROOT = pathlib.Path(__file__).parent.parent
README = (ROOT / "README.md").read_text()


def test_every_case_gets_its_labeled_outcome():
    rows = evaluate.rows()
    assert len(rows) >= 14
    assert all(ok for *_, ok in rows)


def test_committed_fixtures_match_the_generator():
    for name, events in fixtures_gen.FILES.items():
        want = "\n".join(fixtures_gen.lines(events)) + "\n"
        assert (fixtures_gen.OUT / f"{name}.jsonl").read_text() == want, name


def test_every_case_file_exists():
    import json
    for raw in (ROOT / "cases.jsonl").read_text().splitlines():
        assert (fixtures_gen.OUT / f"{json.loads(raw)['file']}.jsonl").exists()


def test_readme_results_table_matches_evaluate_output():
    assert evaluate.results() in README, "README results table drifted from evaluate.py"


def test_readme_lists_every_mutant_and_the_count():
    for name, *_ in mutants.MUTANTS:
        assert f"RED  {name}" in README, f"README misses mutant: {name}"
    assert f"mutants killed {len(mutants.MUTANTS)}/{len(mutants.MUTANTS)}" in README


def test_every_mutant_pattern_exists_exactly_once():
    for name, f, old, new, test in mutants.MUTANTS:
        assert (ROOT / f).read_text().count(old) == 1, name
        assert (ROOT / test).exists(), name


def test_each_required_check_has_a_mutant():
    names = " ".join(m[0] for m in mutants.MUTANTS).lower()
    for word in ("signature", "call", "args", "result", "ttl", "skew", "replay", "receipt", "fail"):
        assert word in names, word
