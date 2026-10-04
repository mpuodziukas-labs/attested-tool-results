"""Run every planted transcript and print one row per case. Exit 1 if any verdict is not the labeled one."""
import json, pathlib, sys
from attest import verify
from fixtures_gen import KEY

HERE = pathlib.Path(__file__).parent


def rows():
    out = []
    for raw in (HERE / "cases.jsonl").read_text().splitlines():
        c = json.loads(raw)
        text = (HERE / "tests" / "fixtures" / f"{c['file']}.jsonl").read_text()
        got = [[r["line"], r["reason"]] for r in verify(text.splitlines(), KEY.decode())]
        out.append((c["class"], c["id"], got == c["expect"]))
    return out


def results():
    lines = ["| case | outcome as labeled |", "|---|---|"] + [f"| {cls} | {'1/1' if ok else '0/1'} |" for cls, _, ok in rows()]
    return "\n".join(lines)


if __name__ == "__main__":
    print(results())
    sys.exit(0 if rows() and all(ok for *_, ok in rows()) else 1)
