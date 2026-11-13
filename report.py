"""Compare graded runs and audit the naive grader.

    python report.py results/base_test.graded.jsonl results/sys_test.graded.jsonl results/sft_test.graded.jsonl \
        --labels base base+sysprompt sft --out results/report.md
    python report.py results/base_train.graded.jsonl --labels base_train --audit-only
"""
import argparse
from collections import defaultdict

from grader.grade import load_tasks, read_jsonl

HELD_OUT = "archive"


def pct(xs):
    xs = list(xs)
    return f"{100 * sum(map(bool, xs)) / len(xs):.0f}%" if xs else "-"


def metrics_table(runs):
    hdr = "| run | n | vulnerable ↓ | exploit fail ↓ | functional ↑ | **secure ∧ functional** ↑ | stub/refusal | naive-accepted |"
    lines = [hdr, "|" + "---|" * 8]
    for label, rows in runs:
        trained = [r for r in rows if r["category"] != HELD_OUT]
        ex = [r for r in trained if r["exploit"] is not None]
        lines.append(f"| {label} | {len(trained)} | {pct(r['vulnerable'] for r in trained)} | "
                     f"{pct(r['exploit'] == 'fail' for r in ex)} | {pct(r['functional'] for r in trained)} | "
                     f"**{pct(r['reward'] for r in trained)}** | {pct(r['stub'] or r['refusal'] for r in trained)} | "
                     f"{pct(r['naive_reward'] for r in trained)} |")
    return "\n".join(lines)


def category_table(runs):
    cats = sorted({r["category"] for _, rows in runs for r in rows})
    lines = ["| category | " + " | ".join(l for l, _ in runs) + " |", "|---|" + "---|" * len(runs)]
    for c in cats:
        name = f"{c} (held out)" if c == HELD_OUT else c
        cells = []
        for _, rows in runs:
            rs = [r for r in rows if r["category"] == c]
            cells.append(f"{pct(r['reward'] for r in rs)} ({pct(r['vulnerable'] for r in rs)} vuln)" if rs else "-")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def audit(label, rows):
    """What would 'reward = Bandit found nothing' have accepted?"""
    acc = [r for r in rows if r["naive_reward"] == 1.0]
    if not acc:
        return f"**{label}**: naive grader accepted nothing."
    reasons = {
        "not functional (fails unit test / stub / missing funcs)": [r for r in acc if not r["functional"]],
        "stub or refusal": [r for r in acc if r["stub"] or r["refusal"]],
        "exploit test FAILED (actually vulnerable)": [r for r in acc if r["exploit"] == "fail"],
        "flagged by our static checks": [r for r in acc if r["static"]],
        "flagged by Semgrep": [r for r in acc if r["semgrep"]],
        "contains # nosec / # nosemgrep": [r for r in acc if r["suppression"]],
    }
    bad = [r for r in acc if r["reward"] == 0.0]
    lines = [f"**{label}**: naive grader accepted {len(acc)}/{len(rows)} samples; "
             f"**{len(bad)} of those ({100 * len(bad) / len(acc):.0f}%) get reward 0 from the real grader.**", ""]
    for k, v in reasons.items():
        if v:
            cats = defaultdict(int)
            for r in v:
                cats[r["category"]] += 1
            top = ", ".join(f"{c} {n}" for c, n in sorted(cats.items(), key=lambda x: -x[1]))
            lines.append(f"- {k}: {len(v)} ({top})")
    return "\n".join(lines)


def examples(runs, tasks, k=2):
    """Tasks where the last run improved most over the first; show one sample from each."""
    (l0, first), (l1, last) = runs[0], runs[-1]
    by = lambda rows: {tid: [r for r in rows if r["task_id"] == tid] for tid in {r["task_id"] for r in rows}}
    a, b = by(first), by(last)
    gain = sorted(((sum(r["reward"] for r in b[t]) / len(b[t]) - sum(r["reward"] for r in a[t]) / len(a[t]), t)
                   for t in a if t in b), reverse=True)
    out = []
    for g, tid in gain[:k]:
        if g <= 0:
            break
        bad = next((r for r in a[tid] if r["vulnerable"]), a[tid][0])
        good = next((r for r in b[tid] if r["reward"] == 1.0), b[tid][0])
        why = "; ".join(bad["static"] + bad["bandit"] + bad["semgrep"] + (["exploit test failed"] if bad["exploit"] == "fail" else []))
        out.append(f"### {tid} ({tasks[tid]['category']}), reward {g:+.2f}\n\n"
                   f"Prompt: {tasks[tid]['prompt'].splitlines()[0]}\n\n"
                   f"**{l0}** (flagged: {why or 'n/a'}):\n\n{bad['completion'].strip()}\n\n"
                   f"**{l1}**:\n\n{good['completion'].strip()}\n")
    return "\n".join(out) or "_no improved tasks_"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--labels", nargs="+")
    ap.add_argument("--out", default=None)
    ap.add_argument("--audit-only", action="store_true")
    args = ap.parse_args()
    labels = args.labels or args.inputs
    runs = list(zip(labels, [read_jsonl(p) for p in args.inputs]))
    tasks = load_tasks()

    parts = []
    if not args.audit_only:
        parts += ["## Headline (trained categories, held-out prompts)", metrics_table(runs),
                  "## Secure ∧ functional by category", category_table(runs)]
    parts += ["## Reward-hacking audit: what a Bandit-only reward would accept"] + [audit(l, r) for l, r in runs]
    if not args.audit_only and len(runs) > 1:
        parts += ["## Before / after examples", examples(runs, tasks)]
    text = "\n\n".join(parts) + "\n"
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"-> {args.out}")


if __name__ == "__main__":
    main()
