"""Regression check: did security training hurt general coding? HumanEval pass@1 (greedy).

    python humaneval.py --n 20 --out results/humaneval_base.json
    python humaneval.py --n 20 --adapter adapters/sft --out results/humaneval_sft.json
"""
import argparse
import json
import os
import re

from datasets import load_dataset

from grader.extract import extract_code
from grader.sandbox import run_program
from mlx_utils import DEFAULT_MODEL, chat_ids, generate_many, load_model

TEMPLATE = ("Complete the following Python function. Return the complete function, including the "
            "signature and any imports, in a single Python code block.\n\n```python\n{prompt}```")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    ds = load_dataset("openai/openai_humaneval", split="test").select(range(args.n))
    model, tok = load_model(args.model, args.adapter)
    ids = [chat_ids(tok, TEMPLATE.format(prompt=p["prompt"])) for p in ds]
    texts = generate_many(model, tok, ids, max_tokens=768, temp=0.0)

    results = []
    for p, text in zip(ds, texts):
        code = extract_code(text, [p["entry_point"]])
        if not re.search(rf"def {re.escape(p['entry_point'])}\s*\(", code):
            code = p["prompt"] + code  # model returned only the body
        # The prompt goes first so its imports exist; the model's def overrides the stub.
        prog = f"{p['prompt']}\n    pass\n\n{code}\n\n{p['test']}\ncheck({p['entry_point']})\n"
        ok, _ = run_program(prog)
        results.append({"task_id": p["task_id"], "passed": ok, "completion": text})
    score = sum(r["passed"] for r in results) / len(results)
    print(f"HumanEval[:{args.n}] pass@1 = {score:.2%}  (adapter={args.adapter})")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"pass@1": score, "adapter": args.adapter, "results": results}, f, indent=1)


if __name__ == "__main__":
    main()
