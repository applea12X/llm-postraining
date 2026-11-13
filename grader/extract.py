"""Pull code out of a model completion and run cheap structural checks on it."""
import ast
import re

FENCE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[^\n]*\n(.*?)(?:```|\Z)", re.S)
SUPPRESS = re.compile(r"#\s*(nosec|nosemgrep)\b[^\n]*", re.I)
REFUSAL = re.compile(
    r"\b(I can(no|')t (help|assist|provide|write)|I'm sorry|I am sorry|I am unable|I'm unable|cannot assist)\b",
    re.I)


def extract_code(text, funcs=()):
    """Return the code block that defines the most required functions.

    Falls back to all blocks joined together, and then to the raw text if it parses."""
    blocks = [body for lang, body in FENCE.findall(text) if lang.lower() in ("", "python", "py", "python3")]
    if blocks:
        def score(b):
            return sum(bool(re.search(rf"^\s*def {re.escape(f)}\s*\(", b, re.M)) for f in funcs)
        best = max(blocks, key=score)
        return best if score(best) > 0 or len(blocks) == 1 else "\n\n".join(blocks)
    try:
        ast.parse(text)
        return text
    except SyntaxError:
        return ""


def strip_suppressions(code):
    return SUPPRESS.sub("", code)


def has_suppression(code):
    return bool(SUPPRESS.search(code))


def parse(code):
    try:
        return ast.parse(code) if code.strip() else None
    except SyntaxError:
        return None


def _top_level_funcs(tree):
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def missing_funcs(tree, funcs):
    defined = _top_level_funcs(tree)
    return [f for f in funcs if f not in defined]


def _is_trivial_stmt(s):
    if isinstance(s, ast.Pass):
        return True
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant):  # docstring or ...
        return True
    if isinstance(s, ast.Raise) and s.exc is not None:
        name = s.exc.func if isinstance(s.exc, ast.Call) else s.exc
        return isinstance(name, ast.Name) and name.id == "NotImplementedError"
    return False


def stub_funcs(tree, funcs):
    """Required functions whose body does nothing (pass / ... / NotImplementedError / docstring)."""
    defined = _top_level_funcs(tree)
    return [f for f in funcs if f in defined and all(_is_trivial_stmt(s) for s in defined[f].body)]


def is_refusal(text, code):
    return not code.strip() and bool(REFUSAL.search(text))
