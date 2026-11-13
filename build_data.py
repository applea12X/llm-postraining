"""Turn graded TRAIN samples into fine-tuning data.

    python build_data.py results/base_train.graded.jsonl results/hint_train.graded.jsonl \\
        --exclude-sources secure

SFT (rejection sampling + context distillation):
  keep samples with reward == 1 (secure AND functional) from any source (plain prompt, teacher
  hint, or the previous adapter's own outputs) and pair them with the PLAIN user prompt. The
  model learns to write the secure version without being told to.

Selection (v2). The first run showed the model copying over-engineering habits from the
generic security prompt, so by default we now:
  - prefer the SHORTEST passing answers per task (fewest lines of code), since extra code that
    the task didn't ask for is where the breakage came from;
  - dedupe on the parsed AST, so answers that differ only in comments count once;
  - train on CLEAN targets: just the implementation in one code block, with module-level demo
    code removed. This is exactly the code the unit and exploit tests ran against.

DPO pairs: chosen = reward 1, rejected = functional but vulnerable. The rejected answer has to
work, so the preference signal is about security and not about "code that runs".
"""
import argparse
import ast
import json
import os
import random
from collections import Counter, defaultdict

from grader.extract import extract_code, strip_demo_code, strip_suppressions
from grader.grade import load_tasks, read_jsonl


def source_of(r):
    return "self" if r.get("adapter") else r["system"]


def clean_code(r, task):
    code = strip_suppressions(extract_code(r["completion"], task["funcs"]))
    return strip_demo_code(code, task["funcs"])[0].strip()


def target_text(r, task, clean):
    return f"```python\n{clean_code(r, task)}\n```" if clean else r["completion"].strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", default="data")
    ap.add_argument("--max-per-task", type=int, default=6, help="cap positives per task to avoid imbalance")
    ap.add_argument("--max-pairs-per-task", type=int, default=4)
    ap.add_argument("--exclude-sources", nargs="*", default=[], help="e.g. secure (the generic security prompt)")
    ap.add_argument("--select", choices=["shortest", "random"], default="shortest")
    ap.add_argument("--no-clean", action="store_true", help="train on the raw completion instead of code only")
    ap.add_argument("--valid-frac", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    tasks = load_tasks()
    clean = not args.no_clean

    rows = [r for p in args.inputs for r in read_jsonl(p)]
    assert all(r["split"] == "train" for r in rows), "refusing to train on test-split samples"
    rows = [r for r in rows if source_of(r) not in args.exclude_sources]

    pos, neg = defaultdict(list), defaultdict(list)
    for r in rows:
        if r["reward"] == 1.0:
            pos[r["task_id"]].append(r)
        elif r["functional"] and r["vulnerable"]:
            neg[r["task_id"]].append(r)

    sft, dpo = [], []
    for tid in sorted({r["task_id"] for r in rows}):
        task = tasks[tid]
        prompt = task["prompt"]
        cands = rng.sample(pos[tid], len(pos[tid]))
        if args.select == "shortest":
            cands.sort(key=lambda r: len([l for l in clean_code(r, task).splitlines() if l.strip()]))
        seen, keep = set(), []
        for r in cands:
            try:
                key = ast.dump(ast.parse(clean_code(r, task)))
            except SyntaxError:
                continue
            if key not in seen:
                seen.add(key)
                keep.append(r)
        keep = keep[: args.max_per_task]
        for r in keep:
            sft.append({"task_id": tid, "source": source_of(r), "messages": [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": target_text(r, task, clean)},
            ]})
        pairs = [(c, j) for c in keep for j in neg[tid]]
        for c, j in rng.sample(pairs, min(len(pairs), args.max_pairs_per_task)):
            dpo.append({"task_id": tid, "prompt": prompt, "chosen": target_text(c, task, clean),
                        "rejected": target_text(j, task, clean)})

    def split_write(name, items, strip_keys=()):
        rng.shuffle(items)
        # mlx-lm needs at least batch_size (4) examples in valid.jsonl
        n_valid = max(4, int(len(items) * args.valid_frac)) if len(items) >= 12 else 0
        d = os.path.join(args.out, name)
        os.makedirs(d, exist_ok=True)
        for fname, part in (("valid.jsonl", items[:n_valid]), ("train.jsonl", items[n_valid:])):
            with open(os.path.join(d, fname), "w") as f:
                for it in part:
                    f.write(json.dumps({k: v for k, v in it.items() if k not in strip_keys}) + "\n")
        print(f"{name}: {len(items) - n_valid} train / {n_valid} valid -> {d}/")
        if n_valid == 0:
            print(f"WARNING: only {len(items)} {name} examples; too few for a validation split")

    # Coverage report: which categories have little or no positive data?
    print("positives per category (unique, capped):")
    cat = Counter(tasks[x["task_id"]]["category"] for x in sft)
    src = Counter(x["source"] for x in sft)
    for c in sorted({t["category"] for t in tasks.values() if t["split"] == "train"}):
        print(f"  {c:<18} {cat.get(c, 0)}")
    print("by source:", dict(src))
    empty = sorted(tid for tid in {r["task_id"] for r in rows} if not pos[tid])
    if empty:
        print(f"WARNING: {len(empty)} train tasks have zero secure+functional samples: {', '.join(empty)}")

    split_write("sft", sft, strip_keys=("task_id", "source"))
    if dpo:
        split_write("dpo", dpo, strip_keys=("task_id",))


if __name__ == "__main__":
    main()
