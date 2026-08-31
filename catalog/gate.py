"""
gate.py — deterministic verification for catalog cards.

Two jobs, both content-blind (no exploit prose ever reaches a manager):
  fill(template, vars)        -> concrete command string (or None if a required {{var}} is missing)
  evaluate(success_if, rc, stdout, stderr) -> True | False | None(indeterminate)

The success_if mini-DSL (as authored in deck_final.yaml):
  atoms:   exit_code ==|!= N   |   IDENT contains 'STR'|"STR"|STR   |   IDENT matches 'REGEX'
  logic:   &&  ||   (also lowercase 'and' / 'or')   with parentheses
  vars:    exit_code, stdout, stderr
Anything outside this grammar (prose gates like "readable directory listing")
returns None = INDETERMINATE. The engine must NOT ground a compromise fact on
an indeterminate gate — it flags the card for human / smarter-AI review instead.
"""
import re

_VARS = {"exit_code", "stdout", "stderr", "response", "output", "report"}  # response/output/report -> stdout alias

class _Indet(Exception): pass

def fill(template, vars):
    """Substitute {{k}}. Returns None if any placeholder has no value (card not fireable yet)."""
    missing = []
    def sub(m):
        k = m.group(1)
        v = vars.get(k)
        if v is None or v == "":
            missing.append(k); return m.group(0)
        return str(v)
    out = re.sub(r"\{\{(\w+)\}\}", sub, template)
    return None if missing else out

def missing_vars(template, vars):
    return [k for k in re.findall(r"\{\{(\w+)\}\}", template)
            if vars.get(k) in (None, "")]

# ---- tokenizer: split on top-level && || and/or and parens, respecting quotes ----
def _tokenize(expr):
    toks, i, n, buf = [], 0, len(expr), ""
    def flush():
        nonlocal buf
        if buf.strip(): toks.append(("ATOM", buf.strip()))
        buf = ""
    while i < n:
        c = expr[i]
        if c in "'\"":
            q = c; buf += c; i += 1
            while i < n and expr[i] != q:
                buf += expr[i]; i += 1
            if i < n: buf += expr[i]; i += 1
            continue
        if c == "(":
            flush(); toks.append(("LP", "(")); i += 1; continue
        if c == ")":
            flush(); toks.append(("RP", ")")); i += 1; continue
        if expr[i:i+2] == "&&":
            flush(); toks.append(("AND", "&&")); i += 2; continue
        if expr[i:i+2] == "||":
            flush(); toks.append(("OR", "||")); i += 2; continue
        if re.match(r"\band\b", expr[i:]) and (i == 0 or not expr[i-1].isalnum()):
            flush(); toks.append(("AND", "and")); i += 3; continue
        if re.match(r"\bor\b", expr[i:]) and (i == 0 or not expr[i-1].isalnum()):
            flush(); toks.append(("OR", "or")); i += 2; continue
        buf += c; i += 1
    flush()
    return toks

def _eval_atom(atom, env):
    a = atom.strip()
    # exit_code ==|!= N
    m = re.fullmatch(r"exit_code\s*(==|!=)\s*(-?\d+)", a)
    if m:
        lhs = env.get("exit_code")
        if lhs is None: raise _Indet()
        return (lhs == int(m.group(2))) if m.group(1) == "==" else (lhs != int(m.group(2)))
    # IDENT contains 'STR' | "STR" | bareword
    m = re.fullmatch(r"(\w+)\s+contains\s+(.+)", a, re.S)
    if m:
        var, rhs = m.group(1), m.group(2).strip()
        if var not in _VARS: raise _Indet()
        hay = env.get("stdout", "") if var in ("response","output","report") else env.get(var, "")
        qm = re.fullmatch(r"'([^']*)'|\"([^\"]*)\"", rhs)
        needle = (qm.group(1) if qm.group(1) is not None else qm.group(2)) if qm else rhs
        # bareword needle with spaces / non-token chars => prose => indeterminate
        if not qm and (not re.fullmatch(r"[\w:./%-]+", needle)):
            raise _Indet()
        return needle in (hay or "")
    # IDENT matches 'REGEX'
    m = re.fullmatch(r"(\w+)\s+matches\s+'([^']*)'|(\w+)\s+matches\s+\"([^\"]*)\"", a)
    if m:
        var = m.group(1) or m.group(3); pat = m.group(2) or m.group(4)
        if var not in _VARS: raise _Indet()
        hay = env.get("stdout","") if var in ("response","output","report") else env.get(var,"")
        try: return re.search(pat, hay or "") is not None
        except re.error: raise _Indet()
    raise _Indet()  # unrecognized -> prose

def _parse(toks, env):
    # recursive descent: OR > AND > primary
    pos = 0
    def primary():
        nonlocal pos
        t = toks[pos]
        if t[0] == "LP":
            pos += 1; v = parse_or()
            if pos < len(toks) and toks[pos][0] == "RP": pos += 1
            return v
        if t[0] == "ATOM":
            pos += 1; return _eval_atom(t[1], env)
        raise _Indet()
    def parse_and():
        nonlocal pos
        v = primary()
        while pos < len(toks) and toks[pos][0] == "AND":
            pos += 1; r = primary(); v = v and r
        return v
    def parse_or():
        nonlocal pos
        v = parse_and()
        while pos < len(toks) and toks[pos][0] == "OR":
            pos += 1; r = parse_and(); v = v or r
        return v
    v = parse_or()
    if pos != len(toks): raise _Indet()
    return v

def evaluate(success_if, exit_code=None, stdout="", stderr=""):
    """True / False / None(indeterminate — prose or unparseable gate)."""
    if not success_if or not success_if.strip():
        return None
    env = {"exit_code": exit_code, "stdout": stdout or "", "stderr": stderr or ""}
    try:
        toks = _tokenize(success_if)
        if not toks: return None
        return bool(_parse(toks, env))
    except _Indet:
        return None
    except Exception:
        return None
