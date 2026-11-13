# Runbook. Each target is one step of PLAN.md. Override e.g. `make baseline N=8`.
PY      := .venv/bin/python
MODEL   ?= Qwen/Qwen2.5-Coder-1.5B-Instruct
N       ?= 4
TEST_N  ?= 8
ADAPTER ?= adapters/sft2
CONFIG  ?= configs/sft2.yaml

.PHONY: tasks test-grader smoke baseline audit hints data train eval humaneval report clean-results

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
	$(PY) gen.py --split test  --n $(TEST_N) --system none   --model $(MODEL) --out results/base_test.jsonl
	$(PY) gen.py --split test  --n $(N) --system secure --model $(MODEL) --out results/sys_test.jsonl
	$(PY) -m grader.grade results/base_train.jsonl results/sys_train.jsonl results/base_test.jsonl results/sys_test.jsonl

audit:            ## what a Bandit-only reward would have accepted
	$(PY) report.py results/base_train.graded.jsonl results/sys_train.graded.jsonl --labels base_train sys_train --audit-only

hints:            ## teacher-hint samples for training data (never used at test time)
	$(PY) gen.py --split train --n 8 --system hint --model $(MODEL) --out results/hint_train.jsonl
	$(PY) -m grader.grade results/hint_train.jsonl

data:             ## step 4a: rejection sampling + context distillation -> data/sft, data/dpo
	$(PY) build_data.py results/base_train.graded.jsonl results/sys_train.graded.jsonl results/hint_train.graded.jsonl \
		$(wildcard results/sft1_train.graded.jsonl) --exclude-sources secure

train:            ## step 4b: LoRA SFT
	$(PY) -m mlx_lm lora -c $(CONFIG) --model $(MODEL) --adapter-path $(ADAPTER)

eval:             ## step 5: held-out prompts with the adapter, then the comparison report
	$(PY) gen.py --split test --n $(TEST_N) --adapter $(ADAPTER) --model $(MODEL) --out results/sft2_test.jsonl
	$(PY) -m grader.grade results/sft2_test.jsonl
	$(MAKE) report

report:
	$(PY) report.py results/base_test.graded.jsonl results/sft2_test.graded.jsonl --labels base sft-v2 --out results/report.md

humaneval:        ## general-coding regression check
	$(PY) humaneval.py --n 40 --model $(MODEL) --out results/humaneval_base.json
	$(PY) humaneval.py --n 40 --model $(MODEL) --adapter $(ADAPTER) --out results/humaneval_sft2.json

clean-results:
	rm -rf results data adapters
