"""Turn graded TRAIN samples into fine-tuning data.

    python build_data.py results/base_train.graded.jsonl results/sys_train.graded.jsonl

SFT (rejection sampling + context distillation):
  keep samples with reward == 1 (secure AND functional), whether they came from the plain or
  the security-system-prompt run, and pair them with the PLAIN user prompt. The model learns
  to act as if it had the security prompt, without needing one.

DPO pairs: chosen = reward 1, rejected = functional but vulnerable. The rejected answer has to
work, so the preference signal is about security and not about "code that runs".
"""
import argparse
import json
import os
import random
from collections import Counter, defaultdict

from grader.grade import load_tasks, read_jsonl
from grader.extract import strip_suppressions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", default="data")
    ap.add_argument("--max-per-task", type=int, default=4, help="cap positives per task to avoid imbalance")
    ap.add_argument("--max-pairs-per-task", type=int, default=4)
    ap.add_argument("--valid-frac", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    tasks = load_tasks()

    rows = [r for p in args.inputs for r in read_jsonl(p)]
    assert all(r["split"] == "train" for r in rows), "refusing to train on test-split samples"

    pos, neg = defaultdict(list), defaultdict(list)
    for r in rows:
        if r["reward"] == 1.0:
            pos[r["task_id"]].append(r)
        elif r["functional"] and r["vulnerable"]:
            neg[r["task_id"]].append(r)

    sft, dpo = [], []
    for tid in sorted({r["task_id"] for r in rows}):
        prompt = tasks[tid]["prompt"]
        seen, keep = set(), []
        for r in rng.sample(pos[tid], len(pos[tid])):
            key = strip_suppressions(r["completion"]).strip()
            if key not in seen:
                seen.add(key)
                keep.append(r)
        keep = keep[: args.max_per_task]
        for r in keep:
            sft.append({"task_id": tid, "source": r["system"], "messages": [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": r["completion"].strip()},
            ]})
        pairs = [(c, j) for c in keep for j in neg[tid]]
        for c, j in rng.sample(pairs, min(len(pairs), args.max_pairs_per_task)):
            dpo.append({"task_id": tid, "prompt": prompt, "chosen": c["completion"].strip(), "rejected": j["completion"].strip()})

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
