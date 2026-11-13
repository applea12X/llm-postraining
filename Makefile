# Runbook. Each target is one step of PLAN.md. Override e.g. `make baseline N=8`.
PY      := .venv/bin/python
MODEL   ?= Qwen/Qwen2.5-Coder-1.5B-Instruct
N       ?= 4
ADAPTER ?= adapters/sft

.PHONY: tasks test-grader smoke baseline audit data train eval humaneval report clean-results

tasks:            ## regenerate prompts/tasks.jsonl from prompts/tasks_src.py
	$(PY) prompts/tasks_src.py

test-grader:      ## references must grade correctly (add SCANNERS=1 for bandit+semgrep)
	$(PY) -m pytest -q tests

smoke:            ## 3 tasks x 1 sample end-to-end
	$(PY) gen.py --split test --n 1 --limit 3 --out results/smoke.jsonl --model $(MODEL)
	$(PY) -m grader.grade results/smoke.jsonl

baseline:         ## step 3: where does the base model write insecure code?
	$(PY) gen.py --split train --n $(N) --system none   --model $(MODEL) --out results/base_train.jsonl
	$(PY) gen.py --split train --n $(N) --system secure --model $(MODEL) --out results/sys_train.jsonl
	$(PY) gen.py --split test  --n $(N) --system none   --model $(MODEL) --out results/base_test.jsonl
	$(PY) gen.py --split test  --n $(N) --system secure --model $(MODEL) --out results/sys_test.jsonl
	$(PY) -m grader.grade results/base_train.jsonl results/sys_train.jsonl results/base_test.jsonl results/sys_test.jsonl

audit:            ## what a Bandit-only reward would have accepted
	$(PY) report.py results/base_train.graded.jsonl results/sys_train.graded.jsonl --labels base_train sys_train --audit-only

data:             ## step 4a: rejection sampling + context distillation -> data/sft, data/dpo
	$(PY) build_data.py results/base_train.graded.jsonl results/sys_train.graded.jsonl

train:            ## step 4b: LoRA SFT
	$(PY) -m mlx_lm lora -c configs/sft.yaml --model $(MODEL) --adapter-path $(ADAPTER)

eval:             ## step 5: held-out prompts with the adapter, then the comparison report
	$(PY) gen.py --split test --n $(N) --adapter $(ADAPTER) --model $(MODEL) --out results/sft_test.jsonl
	$(PY) -m grader.grade results/sft_test.jsonl
	$(MAKE) report

report:
	$(PY) report.py results/base_test.graded.jsonl results/sys_test.graded.jsonl results/sft_test.graded.jsonl \
		--labels base base+sysprompt sft --out results/report.md

humaneval:        ## general-coding regression check
	$(PY) humaneval.py --n 20 --model $(MODEL) --out results/humaneval_base.json
	$(PY) humaneval.py --n 20 --model $(MODEL) --adapter $(ADAPTER) --out results/humaneval_sft.json

clean-results:
	rm -rf results data adapters
