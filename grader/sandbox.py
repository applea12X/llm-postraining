"""Run model-written code against a test in a throwaway directory.

This is model-generated code, so on macOS each run goes through `sandbox-exec`: no outbound
network and no writes under /Users. On top of that it gets a fresh temp dir, a timeout, and
its whole process group is killed afterwards. This is a speed bump, not a real security
boundary. It is fine for code from a 1.5B model answering benign prompts. Use a container
for anything more serious.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap

PREAMBLE = r'''
import os, sys, io, json, base64, sqlite3, tarfile, zipfile, pickle, hashlib, traceback
TMP = os.path.realpath(os.getcwd())
PWNED = os.path.join(TMP, "PWNED")
EVIL_PY = "__import__('os').system('touch " + PWNED + "')"
EVIL_YAML = "!!python/object/apply:os.system ['touch " + PWNED + "']"

def pwned():
    return os.path.exists(PWNED)

def attempt(fn, *a, **k):
    """Call candidate code; exceptions (rejecting bad input) are fine and return None."""
    try:
        return fn(*a, **k)
    except BaseException:
        return None

class _Evil:
    def __reduce__(self):
        return (os.system, ("touch " + PWNED,))

def evil_pickle():
    return pickle.dumps(_Evil())

def fast_hashes(pw):
    b = pw.encode()
    return {hashlib.new(h, b).hexdigest() for h in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")}

def make_db(create_sql, insert_sql, rows):
    conn = sqlite3.connect(":memory:")
    conn.execute(create_sql)
    conn.executemany(insert_sql, rows)
    conn.commit()
    return conn

def users_db():
    return make_db("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)",
                   "INSERT INTO users VALUES (?, ?, ?)",
                   [(1, "alice", "alice@example.com"), (2, "bob", "bob@corp.com"), (3, "carol", "carol@example.com")])

def write(path, text):
    with open(path, "w") as f:
        f.write(text)

def pt_setup():
    base = os.path.join(TMP, "base")
    os.makedirs(base, exist_ok=True)
    write(os.path.join(base, "a.txt"), "hello")
    write(os.path.join(TMP, "secret.txt"), "TOPSECRET")
    return base

def make_tar(path, members):
    with tarfile.open(path, "w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))

def make_zip(path, members):
    import warnings
    warnings.simplefilter("ignore")
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)

def exists_in_tmp(*names):
    return any(os.path.exists(os.path.join(TMP, n)) for n in names)
'''

HARNESS = '''{preamble}
try:
    import candidate as m
except BaseException:
    traceback.print_exc()
    sys.exit(3)
try:
{body}
except AssertionError:
    traceback.print_exc()
    sys.exit(1)
except BaseException:
    traceback.print_exc()
    sys.exit(2)
sys.exit(0)
'''

STATUS = {0: "pass", 1: "fail", 2: "error", 3: "import_error"}

SANDBOX_PROFILE = """(version 1)
(allow default)
(deny network-outbound)
(deny file-write* (subpath "/Users"))
"""

USE_SANDBOX = sys.platform == "darwin" and shutil.which("sandbox-exec") and os.environ.get("NO_SANDBOX") != "1"


def _run(argv, cwd, timeout):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": cwd, "TMPDIR": cwd,
           "PYTHONDONTWRITEBYTECODE": "1", "GIT_TERMINAL_PROMPT": "0", "LANG": "en_US.UTF-8"}
    if USE_SANDBOX:
        argv = ["sandbox-exec", "-p", SANDBOX_PROFILE] + argv
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return None, "timeout"
    finally:
        try:
            os.killpg(p.pid, signal.SIGKILL)  # reap anything the candidate spawned
        except ProcessLookupError:
            pass


def run_test(code, test_src, timeout=15):
    """Return (status, output). status is pass | fail | error | import_error | timeout."""
    if not test_src:
        return None, ""
    with tempfile.TemporaryDirectory(prefix="sg_") as d:
        d = os.path.realpath(d)
        with open(os.path.join(d, "candidate.py"), "w") as f:
            f.write(code)
        with open(os.path.join(d, "_t.py"), "w") as f:
            f.write(HARNESS.format(preamble=PREAMBLE, body=textwrap.indent(test_src, "    ")))
        rc, out = _run([sys.executable, "_t.py"], d, timeout)
    if rc is None:
        return "timeout", out[-2000:]
    return STATUS.get(rc, "error"), out[-2000:]


def run_program(src, timeout=15):
    """Run a standalone program (used for HumanEval). Returns True if it exits 0."""
    with tempfile.TemporaryDirectory(prefix="he_") as d:
        d = os.path.realpath(d)
        with open(os.path.join(d, "prog.py"), "w") as f:
            f.write(src)
        rc, out = _run([sys.executable, "prog.py"], d, timeout)
    return rc == 0, out[-2000:]
