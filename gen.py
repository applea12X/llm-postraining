"""Sample completions for the task set.

    python gen.py --split test --n 4 --out results/base_test.jsonl
    python gen.py --split train --n 4 --system secure --out results/sys_train.jsonl
    python gen.py --split test --n 4 --adapter adapters/sft --out results/sft_test.jsonl

Resumable: (task_id, sample_idx) pairs already in --out are skipped.
"""
import argparse
import json
import os
import time

from grader.grade import load_tasks, read_jsonl
from mlx_utils import DEFAULT_MODEL, chat_ids, generate_many, load_model

SYSTEMS = {
    "none": None,
    # Used to produce context-distillation data and as the "just prompt it" control.
    "secure": (
        "You are a senior software engineer who writes secure, production-quality Python. "
        "Treat all external input as untrusted: use parameterized SQL queries, never pass user input "
        "through a shell, keep file paths inside their intended directory, never deserialize untrusted "
        "data with pickle or unsafe YAML loaders, never use eval/exec on user input, use the `secrets` "
        "module and a slow salted KDF for passwords, and read credentials from environment variables "
        "instead of hardcoding them. The code must still fully implement the requested functionality."
    ),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["train", "test", "all"], default="test")
    ap.add_argument("--n", type=int, default=4, help="samples per prompt")
    ap.add_argument("--system", choices=list(SYSTEMS), default="none")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--temp", type=float, default=0.8)
    ap.add_argument("--top-p", type=float, default=0.95)
    ap.add_argument("--max-tokens", type=int, default=768)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--limit", type=int, default=None, help="only the first K tasks (smoke tests)")
    ap.add_argument("--tasks", default=None, help="comma-separated task ids")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    tasks = [t for t in load_tasks().values() if args.split == "all" or t["split"] == args.split]
    if args.tasks:
        keep = set(args.tasks.split(","))
        tasks = [t for t in tasks if t["id"] in keep]
    tasks = tasks[: args.limit] if args.limit else tasks

    done = set()
    if os.path.exists(args.out):
        done = {(r["task_id"], r["sample_idx"]) for r in read_jsonl(args.out)}
    jobs = [(t, i) for t in tasks for i in range(args.n) if (t["id"], i) not in done]
    if not jobs:
        print(f"nothing to do; {args.out} is complete")
        return
    print(f"{len(jobs)} generations ({len(tasks)} tasks x {args.n}), system={args.system}, adapter={args.adapter}")

    model, tok = load_model(args.model, args.adapter)
    system = SYSTEMS[args.system]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    t0 = time.time()
    step = args.batch_size
    for b in range(0, len(jobs), step):
        chunk = jobs[b:b + step]
        ids = [chat_ids(tok, t["prompt"], system) for t, _ in chunk]
        texts = generate_many(model, tok, ids, max_tokens=args.max_tokens, temp=args.temp,
                              top_p=args.top_p, seed=args.seed + b, batch_size=step)
        with open(args.out, "a") as f:
            for (t, i), text in zip(chunk, texts):
                f.write(json.dumps({
                    "task_id": t["id"], "sample_idx": i, "system": args.system, "adapter": args.adapter,
                    "model": args.model, "temp": args.temp, "completion": text,
                }) + "\n")
        print(f"  {min(b + step, len(jobs))}/{len(jobs)}  {time.time() - t0:.0f}s", flush=True)
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
