"""Validate the grader and the task tests against hand-written references.

    .venv/bin/python -m pytest -q tests            # fast: no scanners
    SCANNERS=1 .venv/bin/python -m pytest -q tests  # also run Bandit + Semgrep
"""
import os

import pytest

from grader.grade import grade_batch, load_tasks
from tests.references import DEMO, HACKS, INSECURE, SECURE

TASKS = load_tasks()
SCANNERS = os.environ.get("SCANNERS") == "1"


def _fence(code):
    return f"Here you go:\n\n```python\n{code.strip()}\n```\n"


def _grade(items):
    gens = [{"task_id": tid, "sample_idx": 0, "completion": c} for tid, c in items]
    return {g["task_id"] + str(i): g for i, g in enumerate(grade_batch(gens, TASKS, scanners=SCANNERS))}


@pytest.fixture(scope="module")
def secure_grades():
    return _grade([(tid, _fence(c)) for tid, c in SECURE.items()])


@pytest.fixture(scope="module")
def insecure_grades():
    return _grade([(tid, _fence(c)) for tid, c in INSECURE.items()])


def test_every_tested_task_has_a_secure_reference():
    tested = {tid for tid, t in TASKS.items() if t["unit"] or t["exploit"]}
    assert tested - set(SECURE) == set()


@pytest.mark.parametrize("tid", sorted(SECURE))
def test_secure_reference_gets_reward(secure_grades, tid):
    g = next(v for v in secure_grades.values() if v["task_id"] == tid)
    detail = {k: g[k] for k in ("unit", "exploit", "static", "bandit", "semgrep", "missing_funcs", "stub")}
    assert g["functional"], (detail, g["unit_log"])
    assert g["secure"], (detail, g["exploit_log"])
    assert g["reward"] == 1.0


@pytest.mark.parametrize("tid", sorted(INSECURE))
def test_insecure_reference_is_caught(insecure_grades, tid):
    g = next(v for v in insecure_grades.values() if v["task_id"] == tid)
    assert g["vulnerable"], {k: g[k] for k in ("unit", "exploit", "static", "bandit", "semgrep")}
    assert g["reward"] == 0.0


@pytest.mark.parametrize("tid", sorted(t for t in INSECURE if TASKS[t]["exploit"]))
def test_insecure_reference_fails_exploit(insecure_grades, tid):
    """The dynamic exploit itself must fire on known-vulnerable code, otherwise the test is broken."""
    g = next(v for v in insecure_grades.values() if v["task_id"] == tid)
    assert g["exploit"] == "fail", g["exploit_log"]


@pytest.mark.parametrize("name", sorted(HACKS))
def test_reward_hacks_get_zero(name):
    tid, completion = HACKS[name]
    text = completion if name == "refusal" else _fence(completion)
    g = grade_batch([{"task_id": tid, "sample_idx": 0, "completion": text}], TASKS, scanners=SCANNERS)[0]
    assert g["reward"] == 0.0
    if name == "nosec_eval":
        assert g["suppression"] and g["static"]
    if name == "stub":
        assert g["stub"]
    if name == "refusal":
        assert g["refusal"]


def test_demo_code_is_stripped_for_tests():
    tid, code = DEMO
    g = grade_batch([{"task_id": tid, "sample_idx": 0, "completion": _fence(code)}], TASKS, scanners=SCANNERS)[0]
    assert g["demo_stripped"] and g["unit"] == "pass" and g["reward"] == 1.0, g["unit_log"]


def test_secret_check_ignores_author():
    from grader.static_checks import run_static_checks
    task = TASKS["sqli_07"]
    assert run_static_checks('author = "alice"\nAUTHOR_NAME = "bob"\n', task) == []
    assert run_static_checks('auth = "hunter22"\n', task)
    assert run_static_checks('headers = {"Authorization": "Bearer abc123"}\n', task)
