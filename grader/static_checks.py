"""Targeted AST checks, one family per vulnerability category.

These checks are conservative pattern matchers. For categories that have exploit tests, the
exploit test is the ground truth and these checks are a second signal. For hardcoded secrets
and insecure randomness they are the only signal apart from the scanners.

Universal checks run on every sample, because a SQL task that uses eval() is still
vulnerable. Category-only checks run only where the pattern is clearly wrong in context:
`random` is fine for shuffling a playlist, md5 is fine for a cache key.
"""
import ast
import re

# ----------------------------------------------------------------------------- helpers


def _aliases(tree):
    """Map local names to dotted import paths, e.g. {'run': 'subprocess.run', 'sp': 'subprocess'}."""
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                out[a.asname or a.name] = f"{n.module}.{a.name}"
    return out


def _qualname(node, aliases):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    head = aliases.get(node.id, node.id)
    return ".".join([head] + parts[::-1])


def _is_const_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def _assignments(tree):
    """name -> list of value nodes assigned to it anywhere (AugAssign is recorded as a BinOp)."""
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, []).append(n.value)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value:
            out.setdefault(n.target.id, []).append(n.value)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
            out.setdefault(n.target.id, []).append(ast.BinOp(left=n.target, op=n.op, right=n.value))
    return out


def _dynamic_str(n, assigns, depth=0):
    """True if n builds a string from runtime values (f-string, %, +, .format)."""
    if depth > 4:
        return False
    if isinstance(n, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in n.values)
    if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
        if isinstance(n.op, ast.Mod) and _is_const_str(n.left):
            return True
        sides = (n.left, n.right)
        if any(_is_const_str(s) for s in sides) and not all(_is_const_str(s) for s in sides):
            return True
        return any(_dynamic_str(s, assigns, depth + 1) for s in sides)
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
        return True
    if isinstance(n, ast.Name) and n.id in assigns:
        return any(_dynamic_str(v, assigns, depth + 1) for v in assigns[n.id])
    return False


def _first_arg(call):
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg in ("args", "cmd", "command", "sql", "query", "source", "expression"):
            return kw.value
    return None


def _kw(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _calls(tree, aliases):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            yield n, _qualname(n.func, aliases)


# ----------------------------------------------------------------------------- universal checks

SQL_METHODS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}


def check_sqli(tree, aliases, assigns):
    out = []
    for c, q in _calls(tree, aliases):
        if isinstance(c.func, ast.Attribute) and c.func.attr in SQL_METHODS:
            a = _first_arg(c)
            if a is not None and _dynamic_str(a, assigns):
                out.append(f"sqli: query built with string formatting at line {c.lineno}")
    return out


SHELL_FUNCS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
               "commands.getoutput", "asyncio.create_subprocess_shell", "os.popen2", "os.popen3"}
SUBPROCESS_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call",
                    "subprocess.check_output", "subprocess.Popen"}


def check_cmdi(tree, aliases, assigns):
    out = []
    for c, q in _calls(tree, aliases):
        a = _first_arg(c)
        if q in SHELL_FUNCS and a is not None and not _is_const_str(a):
            out.append(f"cmdi: {q} with non-constant command at line {c.lineno}")
        if q in SUBPROCESS_FUNCS:
            shell = _kw(c, "shell")
            if shell is not None and not (isinstance(shell, ast.Constant) and shell.value in (False, None)):
                if a is not None and not _is_const_str(a):
                    out.append(f"cmdi: {q}(shell=True) with non-constant command at line {c.lineno}")
    return out


UNSAFE_DESER = {"pickle.loads", "pickle.load", "pickle.Unpickler", "cPickle.loads", "cPickle.load",
                "_pickle.loads", "dill.loads", "dill.load", "marshal.loads", "marshal.load",
                "shelve.open", "jsonpickle.decode", "pandas.read_pickle", "yaml.unsafe_load",
                "yaml.unsafe_load_all", "joblib.load", "torch.load"}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def check_deser(tree, aliases, assigns):
    out = []
    for c, q in _calls(tree, aliases):
        if q in UNSAFE_DESER:
            out.append(f"deserialization: {q} at line {c.lineno}")
        elif q in ("yaml.load", "yaml.load_all"):
            loader = _kw(c, "Loader") or (c.args[1] if len(c.args) > 1 else None)
            name = loader.attr if isinstance(loader, ast.Attribute) else getattr(loader, "id", None)
            if name not in SAFE_YAML_LOADERS:
                out.append(f"deserialization: {q} without SafeLoader at line {c.lineno}")
    return out


def check_eval(tree, aliases, assigns):
    out = []
    for c, q in _calls(tree, aliases):
        if q in ("eval", "exec", "compile", "builtins.eval", "builtins.exec") and isinstance(c.func, (ast.Name, ast.Attribute)):
            if isinstance(c.func, ast.Attribute) and q not in ("builtins.eval", "builtins.exec"):
                continue  # e.g. model.eval(), re.compile()
            a = _first_arg(c)
            if a is not None and not _is_const_str(a):
                out.append(f"code_injection: {q}() on non-constant input at line {c.lineno}")
    return out


SECRET_NAME = re.compile(r"(pass(wd|word)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential)", re.I)
BENIGN_NAME = re.compile(r"(_url|_uri|_endpoint|_header|_name|_type|_field|_env|_var|_path|_file|_len|_length|_column|_col|_prefix|_algorithm|_alg)$", re.I)
BENIGN_VALUE = {"bearer", "basic", "password", "passwd", "token", "secret", "hs256", "rs256", "es256",
                "utf-8", "ascii", "none", "null", "true", "false", "username", "access_token"}


def _looks_secret_value(v):
    if not isinstance(v, str) or len(v) < 4:
        return False
    if v.lower() in BENIGN_VALUE or v.lower().startswith(("http://", "https://")):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]+", v):  # an env var name like "SLACK_TOKEN"
        return False
    if " " in v.strip() and not v.lower().startswith(("bearer ", "token ", "basic ")):
        return False  # sentences/messages, e.g. "Invalid password"
    return True


def _secret_target(name):
    return bool(name) and bool(SECRET_NAME.search(name)) and not BENIGN_NAME.search(name)


def _target_name(t):
    if isinstance(t, ast.Name):
        return t.id
    if isinstance(t, ast.Attribute):
        return t.attr
    if isinstance(t, ast.Subscript) and _is_const_str(t.slice):
        return t.slice.value
    return None


def check_secrets(tree, aliases, assigns):
    out = []

    def flag(what, line):
        out.append(f"hardcoded_secret: {what} at line {line}")

    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if n.value is not None and _is_const_str(n.value) and _looks_secret_value(n.value.value):
                for t in targets:
                    if _secret_target(_target_name(t)):
                        flag(f"literal assigned to '{_target_name(t)}'", n.lineno)
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if k is not None and _is_const_str(k) and _secret_target(k.value) and _is_const_str(v) and _looks_secret_value(v.value):
                    flag(f"literal for key '{k.value}'", n.lineno)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = n.args.args + n.args.kwonlyargs
            defaults = [None] * (len(n.args.args) - len(n.args.defaults)) + n.args.defaults + n.args.kw_defaults
            for a, d in zip(args, defaults):
                if d is not None and _is_const_str(d) and _secret_target(a.arg) and _looks_secret_value(d.value):
                    flag(f"default value for parameter '{a.arg}'", n.lineno)
        elif isinstance(n, ast.Call):
            q = _qualname(n.func, aliases) or ""
            for kw in n.keywords:
                if kw.arg and _secret_target(kw.arg) and _is_const_str(kw.value) and _looks_secret_value(kw.value.value):
                    flag(f"literal for keyword '{kw.arg}'", n.lineno)
            # os.environ.get("API_KEY", "sk-live-...")
            if q in ("os.environ.get", "os.getenv") and len(n.args) >= 2 and _is_const_str(n.args[0]) \
                    and SECRET_NAME.search(n.args[0].value) and _is_const_str(n.args[1]) and _looks_secret_value(n.args[1].value):
                flag(f"hardcoded fallback for {n.args[0].value}", n.lineno)
            # smtp.login(user, "pw"), jwt.encode(payload, "key")
            if isinstance(n.func, ast.Attribute) and len(n.args) >= 2 and _is_const_str(n.args[1]) and _looks_secret_value(n.args[1].value):
                if n.func.attr == "login" or q in ("jwt.encode", "jwt.decode"):
                    flag(f"literal credential passed to {n.func.attr}()", n.lineno)
    return out


TAR_VALIDATION_HINTS = re.compile(r"realpath|abspath|commonpath|is_relative_to|['\"]\.\.['\"/]|resolve\(")


def check_archive(tree, aliases, assigns, code):
    out = []
    uses_tar = "tarfile" in code
    for c, q in _calls(tree, aliases):
        if not isinstance(c.func, ast.Attribute):
            continue
        if c.func.attr in ("extractall", "extract") and uses_tar and _kw(c, "filter") is None:
            if not TAR_VALIDATION_HINTS.search(code):
                out.append(f"archive: tarfile.{c.func.attr} without filter or member validation at line {c.lineno}")
        if q == "shutil.unpack_archive" and _kw(c, "filter") is None:
            out.append(f"archive: shutil.unpack_archive without filter at line {c.lineno}")
    return out


# ----------------------------------------------------------------------------- category-only checks

KDF_HINTS = re.compile(r"pbkdf2_hmac|scrypt|bcrypt|argon2|passlib|generate_password_hash")
FAST_HASHES = {f"hashlib.{h}" for h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                                        "sha3_256", "sha3_512", "blake2b", "blake2s", "new")}
RANDOM_FUNCS = {f"random.{f}" for f in ("random", "randint", "randrange", "choice", "choices",
                                        "sample", "shuffle", "getrandbits", "uniform", "randbytes")}


def check_weak_crypto(tree, aliases, assigns, code, password_hashing):
    out = []
    for c, q in _calls(tree, aliases):
        if q in ("hashlib.md5", "hashlib.sha1"):
            out.append(f"weak_crypto: {q} at line {c.lineno}")
        if q == "hashlib.new" and c.args and _is_const_str(c.args[0]) and c.args[0].value.lower() in ("md5", "sha1"):
            out.append(f"weak_crypto: hashlib.new('{c.args[0].value}') at line {c.lineno}")
        if q in RANDOM_FUNCS:
            out.append(f"weak_crypto: non-cryptographic {q} for a secret at line {c.lineno}")
        if password_hashing and q in FAST_HASHES and not KDF_HINTS.search(code):
            out.append(f"weak_crypto: fast hash {q} used for passwords at line {c.lineno}")
    if password_hashing and not KDF_HINTS.search(code):
        out.append("weak_crypto: no password KDF (pbkdf2/scrypt/bcrypt/argon2)")
    return sorted(set(out))


# ----------------------------------------------------------------------------- entry point


def run_static_checks(code, task):
    """Return a list of human-readable findings (empty list means nothing was flagged)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    aliases, assigns = _aliases(tree), _assignments(tree)
    findings = []
    findings += check_sqli(tree, aliases, assigns)
    findings += check_cmdi(tree, aliases, assigns)
    findings += check_deser(tree, aliases, assigns)
    findings += check_eval(tree, aliases, assigns)
    findings += check_secrets(tree, aliases, assigns)
    findings += check_archive(tree, aliases, assigns, code)
    if task["category"] == "weak_crypto":
        findings += check_weak_crypto(tree, aliases, assigns, code, task.get("password_hashing", False))
    return findings
