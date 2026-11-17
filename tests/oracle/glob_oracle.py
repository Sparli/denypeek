#!/usr/bin/env python3
"""Glob oracle for the denypeek guard: real shells decide what a word reaches.

For every test word, bash, zsh and sh (in each option mode they support) expand it inside a
throwaway fixture home. If any of them reaches a protected path, the hook must deny the command
(must-block). A fixed list of ordinary developer commands must be allowed (must-allow).

Safety
- Everything runs in a fixture home that this script creates under the system temp folder and
  deletes afterwards. HOME is set to it for every shell and for the hook.
- `rm` and `mv` words are only ever expanded with printf, never executed. The only commands that
  really run are the sentinel reads (`cat` of fixture files) in the SENTINEL tier.
- stdin is closed and every process has a timeout. Python 3.9+, standard library only.

Usage
  python3 glob_oracle.py --hook path/to/guard.py [--python /usr/bin/python3]
  python3 glob_oracle.py --hook path/to/guard.sh-or-any-executable --hook-takes-home
  python3 glob_oracle.py --hook ... --quick          # one word per mutation class, fast
  python3 glob_oracle.py --self-test                 # allow-all and deny-all controls
  python3 glob_oracle.py --write-words words.tsv     # regenerate the word list

Exit code: 0 all pass, 1 any failure, 2 usage or environment error.

Hook contract (Claude Code PreToolUse, Bash tool): deny = exit 2, or stdout JSON with
permissionDecision "deny". Allow = exit 0 and no deny. Anything else (crash, timeout, other exit
code) is ERROR and counts as a failure in every tier: Claude Code treats a non-2 error as allow.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
TIMEOUT = 20
SENTINEL = "SENTINEL_9f3c"  # content of every protected fixture file

# --- fixture --------------------------------------------------------------------------------

# The guard's default pattern list (SPEC section 1; as at f4bb7c0 and 5b03394, except that
# `!*.pub` is now the last line, per the spec's 2026-11-17 ruling; byte-identical to 54f8d31). Written to
# the fixture's ~/.denypeek/secretfiles, as a real install does (A25). The oracle never runs the
# installer, so it can judge any commit's hook on its own.
DEFAULT_SECRETFILES = """# denypeek secret files: gitignore-style patterns, one per line. Case does not matter.
# A name with no slash matches at any depth. `~/` is your home folder.
# A line starting with ! allows a path again. Edit, then run: denypeek guard test
.env
.env.*
!.env.example
!.env.sample
!.env.template
.dev.vars
.dev.vars.*
*.pem
*.key
*.p12
*.pfx
id_rsa*
id_dsa*
id_ecdsa*
id_ed25519*
.netrc
.npmrc
.pypirc
credentials.json
service-account*.json
secrets.yml
secrets.yaml
~/.aws/credentials
~/.ssh/**
~/.docker/config.json
~/.kube/config
~/.config/gcloud/**
# Last, so it also allows public keys inside ~/.ssh (the last matching line wins).
!*.pub
"""

# Protected files (default secretfiles patterns, guard self-protection, agent configs), relative
# to the fixture home. "proj/" is the working folder of every command.
PROTECTED_FILES = [
    "proj/.env", "proj/only/.env", "proj/.env.local", "proj/.dev.vars", "proj/server.pem", "proj/tls.key",
    "proj/cert.p12", "proj/id_ed25519", "proj/credentials.json", "proj/secrets.yml",
    "proj/service-account-prod.json", "proj/.npmrc", "proj/.netrc", "proj/.pypirc",
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/known_hosts", "proj/g8/.env", "proj/g8/sub/.env", "proj/g8allow/.env",
    ".aws/credentials", ".docker/config.json", ".kube/config",
    ".config/gcloud/application_default_credentials.json",
    ".denypeek/guard.sh", ".claude/settings.json", ".codex/hooks.json",
    ".cursor/hooks.json", ".gemini/settings.json",
]
# Folders whose deletion or move switches the guard off.
PROTECTED_DIRS = [".denypeek", ".claude", ".codex", ".cursor", ".gemini"]
# Ordinary files: never protected.
ORDINARY_FILES = {
    "proj/README.md": "# demo\n", "proj/config.txt": "API_URL=x\n", "proj/.env.example": "X=\n",
    "proj/src/app.py": "print(1)\n", "proj/src/util.py": "print(2)\n",
    "proj/tests/test_app.py": "def test_a():\n    pass\n", "proj/tests/test_util.py": "",
    "proj/app.pyc": "", "proj/data.json": '{"items": [1]}\n', "proj/log.txt": "ERROR [x]\n",
    "proj/Makefile": "all:\n", "proj/package.json": "{}\n", "proj/notes.md": "n\n",
    "proj/docs/guide.md": "g\n", "proj/key.pub": "ssh-ed25519 AAAA\n",
    ".ssh/id_ed25519.pub": "ssh-ed25519 AAAA\n", "proj/app/[lang]/[id]/page.tsx": "export {}\n",
    "proj/g8/a.txt": "a\n", "proj/g8/b.md": "b\n", "proj/g8/sub/x.txt": "x\n",
    # G8 bare-`*` folder: the only secret is the hidden .env (proj/ also holds non-hidden secrets
    # such as server.pem, where `cat *` really reaches a secret; the author, 2026-11-17).
    "proj/g8allow/a.txt": "a\n", "proj/g8allow/b.md": "b\n", "proj/g8allow/notes/n.txt": "n\n",
    "proj/g8allow/.env.example": "X=\n",
}


HIDDEN = ["always"]  # SPEC 3a G8 setting under test: "always" or "auto" (--hidden)


def make_home() -> Path:
    base = Path(tempfile.mkdtemp(prefix="denypeek-oracle-"))
    real_home = os.path.realpath(os.path.expanduser("~"))
    home = base / "home"
    if os.path.realpath(str(base)).startswith(real_home + os.sep):
        raise SystemExit(f"refusing: temp folder {base} is under the real home folder")
    for rel in PROTECTED_FILES:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{SENTINEL} {rel}\n" if not rel.endswith(".json") else '{"x": "%s"}\n' % SENTINEL)
    for rel, text in ORDINARY_FILES.items():
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    # A real secretfiles with the default list. The sentinel .denypeek/guard.sh is never run;
    # the hook under test is the one passed with --hook.
    (home / ".denypeek/secretfiles").write_text(DEFAULT_SECRETFILES)
    if HIDDEN[0] != "always":  # G8: the fixture selects the setting; missing means "always"
        (home / ".denypeek/guard-state.json").write_text(json.dumps({"hidden_names": HIDDEN[0]}))
    return home


def protected_targets(home: Path) -> set:
    out = {os.path.realpath(str(home / r)) for r in PROTECTED_FILES}
    out.add(os.path.realpath(str(home / ".denypeek/secretfiles")))
    out |= {os.path.realpath(str(home / d)) for d in PROTECTED_DIRS}
    return out


# --- shells ---------------------------------------------------------------------------------


def _bash_major(path: str) -> int:
    v = subprocess.run([path, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, timeout=TIMEOUT).stdout.strip()
    return int(v) if v.isdigit() else 0


def _find_bashes() -> Dict[str, str]:
    """{'bash3': path, 'bash5': path}: the first bash 3.x and the first bash 4+ found."""
    out: Dict[str, str] = {}
    for c in ["/bin/bash", "/usr/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash"]:
        if os.path.exists(c):
            major = _bash_major(c)
            fam = "bash3" if major == 3 else ("bash5" if major >= 4 else None)
            if fam and fam not in out:
                out[fam] = c
    return out


BASH_OPTS = [("", ""), ("+extglob", "shopt -s extglob\n"), ("+nocaseglob", "shopt -s nocaseglob\n"),
             ("+dotglob", "shopt -s dotglob\n"), ("+dotglob+extglob", "shopt -s dotglob extglob\n")]
BASH5_ONLY = [("+globstar", "shopt -s globstar\n"), ("+globstar+dotglob", "shopt -s globstar dotglob\n")]
ZSH_OPTS = [("", ""), ("+extendedglob", "setopt extendedglob\n"), ("+kshglob", "setopt kshglob\n"),
            ("+nocaseglob", "setopt nocaseglob\n"), ("+globdots", "setopt globdots\n"),
            ("+globstarshort", "setopt globstarshort\n"),
            ("+extendedglob+globdots", "setopt extendedglob globdots\n")]
FAMILIES = ("bash3", "bash5", "zsh", "sh")
ALL_MODE_NAMES = (["bash3" + n for n, _ in BASH_OPTS] + ["bash5" + n for n, _ in BASH_OPTS + BASH5_ONLY]
                  + ["zsh" + n for n, _ in ZSH_OPTS] + ["sh"])
LAST_STATS: Dict[str, Tuple[int, int]] = {}
MODE_PROBLEMS: List[str] = []  # modes whose shell exists but whose setup failed


def shell_modes() -> Dict[str, Tuple[str, str]]:
    """name -> (shell binary, setup lines). Modes whose binary or option is missing are dropped
    (and, if the binary exists, listed in MODE_PROBLEMS)."""
    bashes = _find_bashes()
    zsh = shutil.which("zsh") or ("/bin/zsh" if os.path.exists("/bin/zsh") else None)
    wanted = []
    if "bash3" in bashes:
        wanted += [("bash3" + n, bashes["bash3"], s) for n, s in BASH_OPTS]
    if "bash5" in bashes:
        wanted += [("bash5" + n, bashes["bash5"], s) for n, s in BASH_OPTS + BASH5_ONLY]
    if zsh:
        wanted += [("zsh" + n, zsh, s) for n, s in ZSH_OPTS]
    if os.path.exists("/bin/sh"):
        wanted += [("sh", "/bin/sh", "")]
    modes = {}
    MODE_PROBLEMS.clear()
    if os.path.exists("/bin/sh"):
        v = subprocess.run(["/bin/sh", "-c", 'printf %s "${BASH_VERSION:-}"'], capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, timeout=TIMEOUT).stdout.strip()
        SH_IS_BASH[0] = bool(v)
    for name, binary, setup in wanted:
        r = subprocess.run([binary, "-c", setup + "true"], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=TIMEOUT)
        if r.returncode == 0 and not r.stderr.strip():
            modes[name] = (binary, setup)
        else:
            MODE_PROBLEMS.append(name)
            print(f"  mode {name} unavailable: setup failed ({r.stderr.decode().strip()[:80]})")
    return modes


SH_IS_BASH: List[bool] = [False]  # set by shell_modes(): /bin/sh is bash in POSIX mode (macOS)

# Shell features that not every covered shell has. A mode token "sh[bash]" in a case means "sh,
# only when /bin/sh is bash": dash (Linux /bin/sh) has no $'...' quoting and no ~+.
QUALIFIERS = {"bash": ("sh is bash", lambda: SH_IS_BASH[0])}


def _token(tok: str):
    """'sh[bash]' -> ('sh', 'bash'); 'zsh' -> ('zsh', None)."""
    if tok.endswith("]") and "[" in tok:
        base, q = tok[:-1].split("[", 1)
        return base, q
    return tok, None


def resolve_mode(spec: str, modes) -> Optional[str]:
    """'bash5|bash3|sh[bash]' -> the first listed mode that is available and whose stated feature
    the shell has."""
    for tok in spec.split("|"):
        base, q = _token(tok)
        if base in modes and (q is None or QUALIFIERS[q][1]()):
            return base
    return None


def not_applicable(spec: str, modes) -> Optional[str]:
    """Why a case cannot apply on this machine, when the only reason is a stated feature the
    available shell lacks (for example dash and $'...'); None otherwise."""
    reasons = []
    for tok in spec.split("|"):
        base, q = _token(tok)
        if base in modes and q is not None and not QUALIFIERS[q][1]():
            reasons.append(f"{base}: needs '{QUALIFIERS[q][0]}', and it is not")
    return "; ".join(reasons) if reasons and resolve_mode(spec, modes) is None else None


def required_families(arg: Optional[str]) -> List[str]:
    """--require list; 'auto' means what A25 expects on this OS."""
    if not arg:
        return []
    if arg == "auto":
        return ["bash3", "bash5", "zsh", "sh"] if sys.platform == "darwin" else ["bash5", "zsh", "sh"]
    return [x for x in arg.split(",") if x]


def shell_versions(modes) -> List[str]:
    seen, out = set(), []
    for _, (b, _) in modes.items():
        if b in seen:
            continue
        seen.add(b)
        flag = "--version" if "sh" != os.path.basename(b) else "--version"
        r = subprocess.run([b, flag], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=TIMEOUT)
        line = (r.stdout or r.stderr).strip().splitlines()[:1]
        out.append(f"{b}: {line[0] if line else 'unknown'}")
    return out


def env_for(home: Path) -> dict:
    return {"HOME": str(home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def cwd_path(home: Path, rel: str) -> Path:
    return home / rel if rel else home


def expand(binary: str, setup: str, word: str, home: Path, cwd: str = "proj") -> List[str]:
    """What the shell turns `word` into. printf only: nothing named by the word is touched."""
    r = subprocess.run([binary, "-c", setup + "printf '%s\\n' " + word], capture_output=True,
                       text=True, cwd=str(cwd_path(home, cwd)), env=env_for(home),
                       stdin=subprocess.DEVNULL, timeout=TIMEOUT)
    return [line for line in r.stdout.split("\n") if line]


def reaches(results: List[str], home: Path, targets: set, cwd: str = "proj") -> List[str]:
    hit = []
    for g in results:
        p = os.path.realpath(os.path.join(str(cwd_path(home, cwd)), g))
        if p in targets:
            hit.append(p)
    return hit


# --- hook -----------------------------------------------------------------------------------


class Hook:
    def __init__(self, path: str, python: str, takes_home: bool, home: Path):
        self.path, self.python, self.home = path, python, home
        if path.endswith(".py"):
            self.argv = [python, "-I", "-S", path, "--agent", "AGENT", "--home", str(home)]
        elif takes_home:
            self.argv = [path, "--agent", "AGENT", "--home", str(home)]
        else:
            self.argv = [path, "--agent", "AGENT"]
        self.cache: Dict[str, str] = {}

    def decide(self, command: str, cwd: str = "proj", event: Optional[dict] = None, agent: str = "claude") -> str:
        """'deny', 'allow' or 'ERROR: ...'. cwd is relative to the fixture home ('' = home).
        `event` replaces the Bash event (for an agent's own tools, such as Cursor's Delete)."""
        folder = str(cwd_path(self.home, cwd))
        if event is None:
            event = {"cwd": folder, "hook_event_name": "PreToolUse",
                     "tool_name": "Bash", "tool_input": {"command": command}}
        key = agent + "\0" + cwd + "\0" + json.dumps(event, sort_keys=True)
        if key in self.cache:
            return self.cache[key]
        argv = [agent if a == "AGENT" else a for a in self.argv]
        try:
            r = subprocess.run(argv, input=json.dumps(event).encode(), capture_output=True,
                               cwd=folder, env=env_for(self.home), timeout=60)
        except subprocess.TimeoutExpired:
            out = "ERROR: hook timed out"
        else:
            out = _verdict(r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace"))
        self.cache[key] = out
        return out


def _verdict(code: int, stdout: str, stderr: str) -> str:
    if code == 2:
        return "deny"
    if code != 0:
        return f"ERROR: exit {code}: {stderr.strip()[:120]}"
    text = stdout.strip()
    if not text:
        return "ERROR: exit 0 with no output"
    try:
        data = json.loads(text)
    except ValueError:
        return f"ERROR: output is not JSON: {text[:80]}"
    hso = data.get("hookSpecificOutput") if isinstance(data, dict) else None
    if isinstance(hso, dict) and hso.get("permissionDecision") == "deny":
        return "deny"
    if isinstance(data, dict) and data.get("decision") in ("block", "deny"):
        return "deny"
    if isinstance(data, dict) and "permission" in data:  # Cursor: anything but "allow" blocks
        return "allow" if data.get("permission") == "allow" else "deny"
    return "allow"


# --- word generation ------------------------------------------------------------------------


def substitutions(c: str) -> List[Tuple[str, str]]:
    """(class, replacement) for one character c of a name."""
    up = c.upper()
    other = "#"
    subs = [
        ("bracket-literal", f"[{c}]"), ("bracket-neg-bang", f"[!{other}]"), ("bracket-neg-caret", f"[^{other}]"),
        ("bracket-neg-reversed-bang L1", "[!z-a]"), ("bracket-neg-reversed-caret L1", "[^z-a]"),
        ("bracket-neg-x L2", "[^x]" if c != "x" else "[^y]"), ("bracket-leading-close", "[]" + c + "]"),
        ("bracket-neg-leading-close", f"[!]{other}]"), ("bracket-caret-leading-close", f"[^]{other}]"),
        ("question", "?"), ("star", "*"),
        ("class", "[[:alpha:]]" if c.isalpha() else "[[:punct:]]"), ("class-print", "[[:print:]]"),
        ("equiv", f"[[={c}=]]"), ("collating", f"[[.{c}.]]"), ("range-self", f"[{c}-{c}]"),
        ("range-wide", "[a-z]" if c.isalpha() else "[.]"), ("bracket-escaped", f"[\\{c}]"),
        ("bracket-double", f"[[{c}]]"), ("bracket-then-star", f"[{c}]*"),
        ("bracket-slash-neg N2", "[!/]"), ("bracket-slash-caret N2", "[^/]"), ("bracket-slash-member N2", f"[{c}/]"),
        ("escape", "\\" + c), ("dquote", f'"{c}"'), ("squote", f"'{c}'"), ("ansi-c", f"$'{c}'"),
        ("ansi-c-hex", f"$'\\x{ord(c):02x}'"), ("brace-list", f"{{{c},q}}"), ("brace-seq", f"{{{c}..{c}}}"),
        ("empty-squote", f"{c}''"), ("empty-dquote", f'{c}""'),
        ("extglob-at", f"@({c})"), ("extglob-plus", f"+({c})"), ("extglob-q", f"?({c})"), ("extglob-star", f"*({c})"),
        ("extglob-not-hash N1", "!(#)"), ("extglob-not", f"!({other})"),
        ("zsh-group-alt N4", f"({c}|#)"), ("zsh-group N4", f"({c})"),
        ("zsh-repeat N4", f"{c}#"), ("zsh-repeat2 N4", f"{c}##"), ("zsh-not", f"^{other}"),
        ("zsh-icase", "(#i)" + up), ("upper", up), ("bracket-upper", f"[{up}]"),
    ]
    if c in ".-_/":
        subs.append(("zsh-charseq N3", f"{{{c}..{c}}}"))
    return subs


def whole_word_variants(name: str) -> List[Tuple[str, str]]:
    v = [("prefix-star", name[:2] + "*"), ("suffix-star", "*" + name[-2:]),
         ("zsh-exclude", name + "~x"), ("zsh-group-empty", name + "(|x)"), ("zsh-group-whole N4", "(" + name + ")"),
         ("extglob-whole", "@(" + name + ")"), ("extglob-not-any", "!(x)"), ("extglob-dot-not", ".!(x)"),
         ("extglob-star-whole", "*(" + name + ")"), ("brace-last", name[:-1] + "{" + name[-1] + "}"),
         ("brace-empty-alt", "{" + name + ",}"), ("brace-alt", "{x," + name + "}"),
         ("zsh-icase-whole", "(#i)" + name.upper()), ("zsh-not-whole", name[:1] + "^x"),
         ("globstar", "**/" + name), ("globstar-dot", "./**/" + name),
         ("zsh-approx N5", "(#a1)" + name[:-1] + ("w" if name[-1] != "w" else "x")),
         ("zsh-charseq-dot N3", "{....}" + name[1:] if name.startswith(".") else name)]
    if len(name) > 1:
        v += [("two-neg", "[!z-a]" + name[1:-1] + "[^x]"), ("two-q", "?" + name[1:-1] + "[!x]"),
              ("two-caret", "[^#]" + name[1:-1] + "[^#]"), ("two-star-class", "*" + name[1:-1] + "[[:alpha:]]")]
    # Section 3a G3a, G3b, G3c and zsh globstarshort.
    v += [("zsh-repeat-bracket G3a", name + "[x]#"), ("zsh-repeat-group G3a", name + "(x)#"),
          ("zsh-repeat-bracket-mid G3a", name[:-1] + "[q]#" + name[-1]),
          ("zsh-exclude-slash G3b", name[:2] + "*~*/q"),
          ("zsh-group-slash G3c", "(x/)#" + name),
          ("globstarshort", "**" + name), ("globstarshort-tail", "**" + name[-2:])]
    if len(name) > 3:
        v += [("bracket-close-slash G3c", name[:2] + "[!]/]" + name[3:])]
    m = re.search(r"\d+", name)
    if m:  # zsh numeric ranges, on by default in zsh (N7)
        v += [("zsh-numeric N7", name[:m.start()] + "<->" + name[m.end():]),
              ("zsh-numeric-range N7", name[:m.start()] + "<0-99999>" + name[m.end():])]
    return v


def mutate(name: str, quick: bool) -> List[Tuple[str, str]]:
    """(class, word) for name. quick: one position per class."""
    out = []
    positions = range(len(name))
    for i in positions:
        for cls, s in substitutions(name[i]):
            out.append((cls, name[:i] + s + name[i + 1:]))
    out += whole_word_variants(name)
    if quick:  # one word per class: the first position where it applies
        seen, slim = set(), []
        for cls, w in out:
            if cls not in seen:
                seen.add(cls)
                slim.append((cls, w))
        out = slim
    seen, uniq = set(), []
    for cls, w in out:
        if w not in seen:
            seen.add(w)
            uniq.append((cls, w))
    return uniq


# (label, command with {a} for the argument word, argument template with {w} for the mutated
# name, name to mutate, full mutation or one word per class, working folder relative to home)
TARGETS = [
    ("read .env", "cat {a}", "{w}", ".env", True, "proj"),
    ("rm ~/.denypeek", "rm -rf {a}", "~/{w}", ".denypeek", True, "proj"),
    ("rm ~/.claude", "rm -rf {a}", "~/{w}", ".claude", True, "proj"),
    ("mv ~/.claude", "mv {a} /tmp/x", "~/{w}", ".claude", False, "proj"),
    ("rm ~/.codex", "rm -rf {a}", "~/{w}", ".codex", False, "proj"),
    ("rm ~/.cursor", "rm -rf {a}", "~/{w}", ".cursor", False, "proj"),
    ("mv ~/.gemini", "mv {a} /tmp/x", "~/{w}", ".gemini", False, "proj"),
    ("read ~/.ssh/id_rsa via dir", "cat {a}", "~/{w}/id_rsa", ".ssh", False, "proj"),
    ("read ~/.ssh/id_rsa via name", "cat {a}", "~/.ssh/{w}", "id_rsa", False, "proj"),
    ("read ~/.denypeek/guard.sh", "cat {a}", "~/.denypeek/{w}", "guard.sh", False, "proj"),
    ("read .env.local", "cat {a}", "{w}", ".env.local", False, "proj"),
    ("read server.pem", "cat {a}", "{w}", "server.pem", False, "proj"),
    ("read .netrc", "cat {a}", "{w}", ".netrc", False, "proj"),
    ("read ~/.aws/credentials", "cat {a}", "~/.aws/{w}", "credentials", False, "proj"),
    ("read credentials.json", "cat {a}", "{w}", "credentials.json", False, "proj"),
    ("read cert.p12", "cat {a}", "{w}", "cert.p12", False, "proj"),
    ("read id_ed25519", "cat {a}", "{w}", "id_ed25519", False, "proj"),
    # G4: ~+ is the working folder.
    ("rm ~+/.denypeek from home", "rm -rf {a}", "~+/{w}", ".denypeek", False, ""),
    ("rm ~+/.claude from home", "rm -rf {a}", "~+/{w}", ".claude", False, ""),
    ("read ~+/.denypeek/guard.sh from home", "cat {a}", "~+/.denypeek/{w}", "guard.sh", False, ""),
    ("read ~/.denypeek/secretfiles", "cat {a}", "~/.denypeek/{w}", "secretfiles", False, "proj"),
    ("read ~+/.env", "cat {a}", "~+/{w}", ".env", False, "proj"),
]

# G2: a pattern part that starts with "." can match "." and ".." (bash before 5.2, macOS /bin/sh).
# (label, class, word, command, working folder)
DOT_DIR_ROWS = [
    ("read .env via . or ..", "dotdir-star G2", ".*/.en?", "cat .*/.en?", "proj"),
    ("read .env via . or ..", "dotdir-star G2", ".*/.env", "cat .*/.env", "proj"),
    ("read .env via . or ..", "dotdir-q G2", ".?/.en?", "cat .?/.en?", "proj/src"),
    ("read .env via . or ..", "dotdir-q G2", ".?/.env", "cat .?/.env", "proj/src"),
    ("read .env via . or ..", "dotdir-bracket G2", ".[.]/.env", "cat .[.]/.env", "proj/src"),
    ("read .env via . or ..", "dotdir-bracket G2", ".[!x]/.env", "cat .[!x]/.env", "proj/src"),
    ("read .env via . or ..", "dotdir-star G2", ".*/.env", "cat .*/.env", "proj/src"),
    ("read .env via . or ..", "dotdir-sub G2", "src/.?/.env", "cat src/.?/.env", "proj"),
    ("read .env via . or ..", "dotdir-sub G2", "src/.*/.en?", "cat src/.*/.en?", "proj"),
    ("rm ~/.denypeek via ..", "dotdir-q G2", "~/.claude/.?/.denypeek", "rm -rf ~/.claude/.?/.denypeek", "proj"),
    ("rm ~/.denypeek via ..", "dotdir-star G2", "~/.claude/.*/.denypeek", "rm -rf ~/.claude/.*/.denypeek", "proj"),
    ("rm ~/.claude via ..", "dotdir-q G2", "~/.codex/.?/.claude", "rm -rf ~/.codex/.?/.claude", "proj"),
    ("mv ~/.gemini via ..", "dotdir-q G2", "~/.cursor/.?/.gemini", "mv ~/.cursor/.?/.gemini /tmp/x", "proj"),
    ("read ~/.ssh/id_rsa via ..", "dotdir-q G2", "~/.claude/.?/.ssh/id_rsa", "cat ~/.claude/.?/.ssh/id_rsa", "proj"),
    ("read ~/.ssh/id_rsa via ..", "dotdir-star G2", "~/.claude/.*/.ssh/id_rs?", "cat ~/.claude/.*/.ssh/id_rs?", "proj"),
]


# Words that combine two or three mutation classes in one name (added 2026-11-17 after fresh
# words found C1 and C2: each feature alone was denied, the combination was not). Seeded, so the
# list is reproducible; the class column names every class used.
COMBO_SEED = 20261117
COMBO_PER_TARGET = 30
COMBO_TARGETS = TARGETS + [
    ("read ~/.gemini/settings.json", "cat {a}", "~/.gemini/{w}", "settings.json", False, "proj"),
    ("read ~/.claude/settings.json", "cat {a}", "~/.claude/{w}", "settings.json", False, "proj"),
    ("read .npmrc", "cat {a}", "{w}", ".npmrc", False, "proj"),
    ("read .dev.vars", "cat {a}", "{w}", ".dev.vars", False, "proj"),
    ("read tls.key", "cat {a}", "{w}", "tls.key", False, "proj"),
    ("read ~/.kube/config", "cat {a}", "~/.kube/{w}", "config", False, "proj"),
]


def combos(quick: bool) -> List[Tuple[str, str, str, str, str]]:
    import random
    rnd = random.Random(COMBO_SEED)
    rows, seen = [], set()
    per = 4 if quick else COMBO_PER_TARGET
    for label, cmd, arg, name, _full, cwd in COMBO_TARGETS:
        made = tries = 0
        while made < per and tries < per * 20:
            tries += 1
            chars, used = list(name), []
            for i in sorted(rnd.sample(range(len(name)), min(rnd.choice([2, 2, 3]), len(name))), reverse=True):
                cls, sub = rnd.choice(substitutions(name[i]))
                chars[i] = sub
                used.append(cls.split()[0])
            word = arg.format(w="".join(chars))
            if word in seen:
                continue
            seen.add(word)
            rows.append((label, "combo:" + "+".join(sorted(used)), word, cmd.format(a=word), cwd))
            made += 1
    return rows


def generate(quick_all: bool = False) -> List[Tuple[str, str, str, str, str]]:
    """(target label, class, argument word exactly as in the command, command, working folder)."""
    rows = []
    for label, cmd, arg, name, full, cwd in TARGETS:
        for cls, w in mutate(name, quick=quick_all or not full):
            word = arg.format(w=w)
            rows.append((label, cls, word, cmd.format(a=word), cwd))
    rows += DOT_DIR_ROWS
    known = {r[2] for r in rows}
    rows += [r for r in combos(quick_all) if r[2] not in known]
    return rows


def write_words(path: Path, rows) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("# target\tclass\tword\tcommand\tcwd (relative to the fixture home; empty = home)  (generated by glob_oracle.py --write-words)\n")
        for r in rows:
            f.write("\t".join(r) + "\n")


def read_words(path: Path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) == 4:
            parts.append("proj")
        rows.append(tuple(parts))
    return rows


# --- named cases ----------------------------------------------------------------------------

# (id, shell mode spec ("a|b": the first available), command, word to expand, target relative
# to home, working folder relative to home). The mode must really reach the target (precondition).
B = "bash5|bash3"
BX = "bash5+extglob|bash3+extglob"
NAMED = [
    ("L1-bang", B, "cat .en[!z-a]", ".en[!z-a]", "proj/.env", "proj"),
    ("L1-caret", B, "cat .en[^z-a]", ".en[^z-a]", "proj/.env", "proj"),
    ("L1-rm-denypeek", "zsh", "rm -rf ~/.denype[!z-a]k", "~/.denype[!z-a]k", ".denypeek", "proj"),
    ("L2-caret", B, "cat .en[^x]", ".en[^x]", "proj/.env", "proj"),
    ("L2-rm-claude", "zsh", "rm -rf ~/.clau[^x]e", "~/.clau[^x]e", ".claude", "proj"),
    ("L2-mv-denypeek", B, "mv ~/.denype[^x]k /tmp/x", "~/.denype[^x]k", ".denypeek", "proj"),
    ("N1-extglob", BX, "cat .!(#)nv", ".!(#)nv", "proj/.env", "proj"),
    ("N1-kshglob", "zsh+kshglob", "rm -rf ~/.!(#)enypeek", "~/.!(#)enypeek", ".denypeek", "proj"),
    ("N2-zsh-bang-slash", "zsh", "cat .e[!/]v", ".e[!/]v", "proj/.env", "proj"),
    ("N2-zsh-caret-slash", "zsh", "cat .en[^/]", ".en[^/]", "proj/.env", "proj"),
    ("N2-zsh-member-slash", "zsh", "cat .[e/]nv", ".[e/]nv", "proj/.env", "proj"),
    ("N3-zsh-charseq", "zsh", "cat {....}env", "{....}env", "proj/.env", "proj"),
    ("N3-zsh-charseq-rm", "zsh", "rm -rf ~/{....}denypeek", "~/{....}denypeek", ".denypeek", "proj"),
    ("N4-zsh-group", "zsh", "rm -rf ~/(.)claude", "~/(.)claude", ".claude", "proj"),
    ("N4-zsh-group-inner", "zsh", "rm -rf ~/.c(l)aude", "~/.c(l)aude", ".claude", "proj"),
    ("N4-zsh-repeat", "zsh+extendedglob", "rm -rf ~/.cl#aude", "~/.cl#aude", ".claude", "proj"),
    ("N4-zsh-icase", "zsh+extendedglob", "rm -rf ~/(#i).CLAUDE", "~/(#i).CLAUDE", ".claude", "proj"),
    ("N4-extglob", BX, "rm -rf ~/.c@(l)aude", "~/.c@(l)aude", ".claude", "proj"),
    ("N5-zsh-approx", "zsh+extendedglob", "cat (#a1).enw", "(#a1).enw", "proj/.env", "proj"),
    ("N6-ansi-c-rm-claude", "sh[bash]", "rm -rf ~/.c$'l'aude", "~/.c$'l'aude", ".claude", "proj"),
    ("N6-ansi-c-rm-claude-bash", B, "rm -rf ~/.c$'l'aude", "~/.c$'l'aude", ".claude", "proj"),
    ("N6-ansi-c-hex-mv-gemini", B, "mv ~/$'\\x2e'gemini /tmp/x", "~/$'\\x2e'gemini", ".gemini", "proj"),
    ("N6-ansi-c-rm-codex", "zsh", "rm -rf ~/.co$'d'ex", "~/.co$'d'ex", ".codex", "proj"),
    ("N7-zsh-numeric", "zsh", "cat cert.p<->", "cert.p<->", "proj/cert.p12", "proj"),
    ("N7-zsh-numeric-key", "zsh", "cat id_ed<->", "id_ed<->", "proj/id_ed25519", "proj"),
    # the spec, SPEC section 3a "Open today" (2026-11-15).
    ("H1-tildeplus-rm-bash", B, "rm -rf ~+/.denypeek", "~+/.denypeek", ".denypeek", ""),
    ("H1-tildeplus-rm-sh", "sh[bash]", "rm -rf ~+/.denypeek", "~+/.denypeek", ".denypeek", ""),
    ("H1-tildeplus-rm-zsh", "zsh", "rm -rf ~+/.denypeek", "~+/.denypeek", ".denypeek", ""),
    ("H2-tildeplus-cat-zsh", "zsh", "cat ~+/.denypeek/secretfiles", "~+/.denypeek/secretfiles", ".denypeek/secretfiles", ""),
    # In a folder that holds only .env (with .env.local beside it, a cruder rewrite denies it by luck).
    ("H3-zsh-repeat-bracket", "zsh+extendedglob", "cat .env[x]#", ".env[x]#", "proj/only/.env", "proj/only"),
    ("H4-dotdir-star", "bash3|sh", "cat .*/.en?", ".*/.en?", "proj/.env", "proj"),
    ("H5-dotdir-q-subfolder", "bash3|sh", "cat .?/.en?", ".?/.en?", "proj/.env", "proj/src"),
    ("H6-dotdir-agent", "bash3|sh", "rm -rf ~/.claude/.?/.denypeek", "~/.claude/.?/.denypeek", ".denypeek", "proj"),
    # G3b, G3c and globstarshort words, one each.
    ("G3b-zsh-exclude-slash", "zsh+extendedglob", "cat .e*~*/q", ".e*~*/q", "proj/.env", "proj"),
    ("G3c-zsh-group-slash", "zsh+extendedglob", "cat (x/)#.env", "(x/)#.env", "proj/.env", "proj"),
    ("G3c-zsh-bracket-close-slash", "zsh", "cat .e[!]/]v", ".e[!]/]v", "proj/.env", "proj"),
    ("GS-zsh-globstarshort", "zsh+globstarshort", "cat **.pem", "**.pem", "proj/server.pem", "proj"),
    # Found 2026-11-17 by fresh combination words against 0ea7c2b.
    ("C1-group-slashbracket-subfolder", "zsh", "cat ~/.gemini/se(t)tings.[^/]son", "~/.gemini/se(t)tings.[^/]son", ".gemini/settings.json", "proj"),
    ("C2-repeat-slashbracket-bracket", "zsh+extendedglob", "cat .e##[^/][^x]", ".e##[^/][^x]", "proj/.env", "proj"),
]

# Commands that really run (cat of fixture files only); must-block when the output holds the
# sentinel. Covers globs that are quoted first and expanded later.
SENTINEL_CASES = [  # (id, mode spec, command, working folder)
    ("G1-var-star", B, "a='.e*'; cat $a", "proj"),
    ("G1-var-bracket", B, "a='[!x]'; cat .en$a", "proj"),
    ("G1-var-question", "sh", "a='?'; cat .en$a", "proj"),
    ("G1-var-zsh-tilde", "zsh", "a='.e*'; cat $~a", "proj"),
    # the spec, SPEC 3a "Open at 5b03394": quoted patterns the shell reads again (G1a, G1b).
    ("G1-for-quoted", "bash3|sh", "for f in '.e*'; do cat $f; done", "proj"),
    ("G1-set-quoted", "bash3|sh", "set -- '.e*'; cat $1", "proj"),
    ("G1-array-quoted", "bash3|bash5", "a=('.e*'); cat ${a[0]}", "proj"),
    ("G1-sh-c-arg", "bash3|sh", "sh -c 'cat $0' '.e*'", "proj"),
    ("G1-eval-quoted", "bash3|sh", "eval cat '.e*'", "proj"),
    ("G1-eval-escaped", "bash3|sh", "eval cat .e\\*", "proj"),
    ("G1-pipe-to-sh", "bash3|sh", "echo 'cat .e*' | sh", "proj"),
    # Public keys pass, private keys and known_hosts do not (default list, the spec 2026-11-17).
    ("ssh-private-key", B, "cat ~/.ssh/id_ed25519", "proj"),
    ("ssh-private-key-star", B, "cat ~/.ssh/id_ed25519*", "proj"),
    ("ssh-star", B, "cat ~/.ssh/*", "proj"),
    ("ssh-known-hosts", B, "cat ~/.ssh/known_hosts", "proj"),
    ("array", B, "x=(.e?v); cat ${x[0]}", "proj"),
    ("set-args", "sh", "set -- .e[!x]v; cat $1", "proj"),
    ("for-loop", B, "for f in .e?v; do cat $f; done", "proj"),
    ("cmd-subst", B, "cat $(echo .e?v)", "proj"),
    ("backticks", B, "cat `echo .e[!x]v`", "proj"),
    ("bash-c", B, "bash -c 'cat .e?v'", "proj"),
    ("sh-c", B, "sh -c \"cat .en[!x]\"", "proj"),
    ("zsh-c", B, "zsh -c 'cat .e[!/]v'", "proj"),
    ("eval", B, "eval 'cat .e*'", "proj"),
    ("eval-dq", B, "eval \"cat .en[^x]\"", "proj"),
    ("zsh-qualifier", "zsh", "cat *(D.)", "proj"),
    ("zsh-exclude", "zsh+extendedglob", "cat .e*~*.example~*.local", "proj"),
    ("dotglob-star", "bash5+dotglob|bash3+dotglob", "cat *v", "proj"),
    ("globstar", "zsh", "cat **/.e?v", "proj"),
    ("nocase", "bash5+nocaseglob|bash3+nocaseglob", "cat .EN?", "proj"),
]

# G7 (SPEC 3a): delete, move or lock the home folder or a folder above it. Must-block. Nothing
# here is ever run: the precondition expands only the operand word with printf and checks that it
# resolves to the home folder or one of its ancestors.
# (id, mode spec, command, operand word, working folder)
ANCESTOR_CASES = [
    ("G7-rm-dotdot", B, "rm -rf ..", "..", "proj"),
    ("G7-rm-dot-q", "bash3|sh", "rm -rf .?", ".?", "proj"),
    ("G7-rm-tilde", B, "rm -rf ~", "~", "proj"),
    ("G7-rm-tilde-slash", B, "rm -rf ~/", "~/", "proj"),
    ("G7-rm-home-var", B, "rm -rf $HOME", "$HOME", "proj"),
    ("G7-rm-above-home", B, "rm -rf ~/..", "~/..", "proj"),
    ("G7-rm-dot-from-home", B, "rm -rf .", ".", ""),
    ("G7-rm-tildeplus-from-home", B, "rm -rf ~+", "~+", ""),
    ("G7-sudo-rm", B, "sudo rm -rf ~", "~", "proj"),
    ("G7-env-rm", B, "env rm -rf ~", "~", "proj"),
    ("G7-abs-rm", B, "/bin/rm -rf ~", "~", "proj"),
    ("G7-backslash-rm", B, "\\rm -rf ~", "~", "proj"),
    ("G7-rmdir", B, "rmdir ~", "~", "proj"),
    ("G7-unlink", B, "unlink ~", "~", "proj"),
    ("G7-shred", B, "shred -u ~", "~", "proj"),
    ("G7-trash", B, "trash ~", "~", "proj"),
    ("G7-mv-home", B, "mv ~ /tmp/x", "~", "proj"),
    ("G7-mv-target-dir", B, "mv -t /tmp/x ~", "~", "proj"),
    ("G7-mv-target-dir-long", B, "mv --target-directory=/tmp/x ~", "~", "proj"),
    ("G7-chmod", B, "chmod -R 000 ~", "~", "proj"),
    ("G7-chown", B, "chown -R nobody ~", "~", "proj"),
    ("G7-chgrp", B, "chgrp -R nobody ~", "~", "proj"),
    ("G7-chflags", B, "chflags -R uchg ~", "~", "proj"),
    ("G7-git-clean-home", B, "git clean -fdx", ".", ""),
    ("G7-git-clean-C", B, "git -C ~ clean -fdx", "~", "proj"),
    ("G7-git-clean-cd", B, "cd ~ && git clean -fdx", "~", "proj"),
    ("G7-rsync-delete", B, "rsync -a --delete empty/ ~/", "~/", "proj"),
    ("G7-rsync-delete-after", B, "rsync -a --delete-after empty/ ~/", "~/", "proj"),
    ("G7-rsync-remove-source", B, "rsync -a --remove-source-files ~/ /tmp/x", "~/", "proj"),
    ("G7-find-delete", B, "find ~ -delete", "~", "proj"),
    ("G7-find-exec", B, "find ~ -exec rm -rf {} +", "~", "proj"),
    ("G7-cursor-delete-tool", "", "Cursor Delete tool on the home folder", "", "proj"),
]

# Must-allow: ordinary work in a folder that holds .env. (id, command)
MUST_ALLOW = [
    ("ls-py", "ls src/*.py"), ("ls-py-cwd", "ls *.py"), ("cat-md", "cat *.md"), ("rm-pyc", "rm -f *.pyc"),
    ("pytest-glob", "pytest tests/test_*.py"), ("git-add-glob", "git add src/*.py"),
    ("grep-regex-star", "grep -o '[a-z]*' README.md"), ("grep-ere-anchor", 'grep -E "^[A-Z_]+=" config.txt'),
    ("test-bracket", "[ -f README.md ] && echo ok"), ("test-double", "[[ -n $x ]] && echo ok"),
    ("array-index", "echo ${arr[0]}"), ("array-all", "arr=(a b); echo ${arr[@]}"),
    ("find-name", 'find . -name "*.py"'), ("find-name-sq", "find . -name '*.md' -type f"),
    ("echo-quoted-star", "echo '*'"), ("echo-quoted-glob", "echo '.e*'"),
    ("git-diff-pathspec", "git diff -- '*.py'"), ("git-diff-head", "git diff HEAD~1"),
    ("git-reset-caret", "git reset HEAD^"), ("git-stash-show", "git stash show stash@{0}"),
    ("git-log-format", "git log --format='[%h] %s' -n 3"), ("pip-extra", "pip install 'pkg[extra]'"),
    ("pip-extra-unquoted-dq", 'pip install "pkg[dev,test]"'), ("curl-query", "curl 'https://example.com/y?a=1#frag'"),
    ("if-not-grep", "if ! grep -q x README.md; then echo no; fi"), ("arith", "echo $((1+2))"),
    ("npm-scope", "npm i @scope/pkg"), ("sed-regex", "sed -n 's/[a-z]*//p' README.md"),
    ("tr-class", "tr '[:lower:]' '[:upper:]' < README.md"), ("jq-index", "jq '.items[0]' data.json"),
    ("awk-field", "awk '{print $1}' README.md"), ("brace-mkdir", "mkdir -p out/{a,b}"),
    ("brace-seq-echo", "echo {1..3}"), ("pytest-k", "pytest -k 'test_[a-z]'"),
    ("ls-bracket-src", "ls src/[a-z]*.py"), ("cat-question-src", "cat src/?pp.py"),
    ("python-list", "python3 -c 'print([1, 2][0])'"), ("python-regex", "python3 -c \"import re; print(re.findall('[a-z]+', 'ab'))\""),
    ("cat-env-example", "cat .env.example"), ("ls-la", "ls -la"), ("cp-src", "cp src/app.py src/app2.py"),
    ("rm-build", "rm -rf build"), ("make", "make test"), ("npm-test", "npm test -- --grep '[slow]'"),
    ("docker-ps-format", "docker ps --format '{{.Names}}'"), ("echo-caret", "echo x^2"),
    ("redirect-out", "echo hi > out.txt"), ("ls-docs-star", "ls docs/*"), ("wc-md", "wc -l *.md docs/*.md"),
    ("git-checkout-dash", "git checkout -- src/app.py"), ("pub-key", "cat key.pub"),
    # SPEC section 3a "What must stay allowed", added 2026-11-17.
    ("rm-pyc-plain", "rm *.pyc"), ("pip-editable-extra", "pip install -e .[dev]"),
    ("param-count", "echo $#"), ("param-index", "echo ${x[1]}"), ("param-strip", "v=abc; echo ${v#a}"),
    ("param-upper", "v=abc; echo ${v^^}"), ("array-assign", "x=(a b c)"), ("subshell", "(cd src && ls)"),
    ("test-bracket-x", "[ -f x ] && echo y"), ("url-hash", "curl https://example.com/docs#top"),
    ("url-query", "curl https://example.com/api?q=1"), ("git-range", "git log HEAD~1..HEAD"),
    ("git-show-caret-path", "git show HEAD^:README.md"), ("find-name-plain-sq", "find . -name '*.py'"),
    # SPEC 3a G7 must-allow, added 2026-11-17.
    ("g7-mv-into-home", "mv notes.md ~"), ("g7-cp-into-home", "cp README.md ~"), ("g7-ls-parent", "ls .."),
    ("g7-cd-home-ls", "cd ~ && ls"), ("g7-chmod-file-in-home", "chmod +x ~/bin/tool"),
    ("g7-rm-build-in-home", "rm -rf ~/proj/build"), ("g7-rm-dot-cache", "rm -rf .*_cache"),
    ("g7-git-clean-project", "git clean -fd"), ("g7-find-home-name", "find ~ -name x"),
    # the spec 2026-11-17: G3c tree walk, G2 `*/name`, public keys.
    ("g3c-nested-dynamic-route", "cat app/[lang]/[id]/page.tsx"), ("g2-ls-dirs", "ls */"),
    ("g2-ls-d-dirs", "ls -d */"), ("g2-ls-star-name", "ls */README.md"), ("g2-rm-star-pycache", "rm -rf */__pycache__"),
    ("pubkey-one", "cat ~/.ssh/id_ed25519.pub"), ("pubkey-star", "cat ~/.ssh/*.pub"),
]

# G8 (SPEC 3a): bare `*` beside a hidden secret file, run in proj/g8allow, whose only secret is
# .env. In "always" these are expected denies (with dotglob or globdots they reach .env); in "auto"
# they must be allowed.
G8_ALLOW_CWD = "proj/g8allow"
G8_BARE_STAR = ["du -sh *", "cat *", "wc -l *", "grep foo *", "rm -rf ./*"]
AUTO_MUST_ALLOW = [("auto-" + c.split()[0] + str(i), c) for i, c in enumerate(G8_BARE_STAR)] + [
    ("auto-pipefail-ls", "set -euo pipefail; ls *"), ("auto-nullglob-ls", "shopt -s nullglob; ls *.py"),
    ("auto-extendedglob-ls", "setopt extendedglob; ls *.py"), ("auto-ls-star", "ls *"), ("auto-echo-star", "echo *"),
]

# G8 "auto": switch forms. Each runs for real (only `cat` or `grep` of fixture files, in proj/g8,
# which holds .env, sub/.env and plain files) and must print a protected sentinel; then the hook
# must deny it. "H" = the spec's list (2026-11-17): a failed precondition is a failure. "V" = the review's
# attack forms: a failed precondition means the form does not work there (reported, not failed).
# {bash5} is replaced by the bash 5 binary. (id, origin, mode spec, command)
G8_SWITCH = [
    ("H-shopt", "H", B, "shopt -s dotglob; cat *"),
    ("H-bash-O", "H", B, "bash -O dotglob -c 'cat *'"),
    # Run from zsh: in bash, BASHOPTS is read-only, so the prefix assignment fails there.
    ("H-BASHOPTS", "H", "zsh", "BASHOPTS=dotglob {bash5} -c 'cat *'"),
    ("H-GLOBIGNORE", "H", B, "GLOBIGNORE=zz; cat *"),
    ("H-GLOBIGNORE-export", "H", B, "export GLOBIGNORE=zz; cat *"),
    ("H-GLOBIGNORE-declare", "H", B, "declare GLOBIGNORE=zz; cat *"),
    ("H-GLOBIGNORE-read", "H", B, "read GLOBIGNORE <<< zz; cat *"),
    ("H-setopt-globdots", "H", "zsh", "setopt globdots; cat *"),
    ("H-setopt-GLOB_DOTS", "H", "zsh", "setopt GLOB_DOTS; cat *"),
    ("H-setopt-mixed", "H", "zsh", "setopt g_lObd_ots; cat *"),
    ("H-setopt-dotglob", "H", "zsh", "setopt dotglob; cat *"),
    ("H-unsetopt-no", "H", "zsh", "unsetopt noglobdots; cat *"),
    ("H-set-o", "H", "zsh", "set -o globdots; cat *"),
    ("H-set-plus-o-no", "H", "zsh", "set +o noglobdots; cat *"),
    ("H-setopt-4", "H", "zsh", "setopt -4; cat *"),
    ("H-set-4", "H", "zsh", "set -4; cat *"),
    ("H-zsh-4", "H", "zsh", "zsh -4 -c 'cat *'"),
    ("H-zsh-f4c", "H", "zsh", "zsh -f4c 'cat *'"),
    ("H-zsh-o", "H", "zsh", "zsh -o globdots -c 'cat *'"),
    ("H-zsh-plus-o-no", "H", "zsh", "zsh +o noglobdots -c 'cat *'"),
    ("H-zsh-long", "H", "zsh", "zsh --globdots -c 'cat *'"),
    ("H-emulate", "H", "zsh", "emulate zsh -o globdots; cat *"),
    ("H-options-assign", "H", "zsh", "options[globdots]=on; cat *"),
    ("H-options-append", "H", "zsh", "options+=(globdots on); cat *"),
    # the review's attack forms.
    ("V-shopt-multi", "V", B, "shopt -s nullglob dotglob; cat *"),
    ("V-shopt-q", "V", B, "shopt -qs dotglob; cat *"),
    ("V-shopt-continuation", "V", B, "shopt -s dot\\\nglob; cat *"),
    ("V-shopt-quoted", "V", B, "shopt -s 'dot'\"glob\"; cat *"),
    ("V-shopt-escaped", "V", B, "shopt -s dot\\glob; cat *"),
    ("V-shopt-ansi-hex", "V", B, "shopt -s $'dot\\x67lob'; cat *"),
    ("V-shopt-var", "V", B, "o=dotglob; shopt -s $o; cat *"),
    ("V-shopt-var-split", "V", B, "o=dot; shopt -s ${o}glob; cat *"),
    ("V-shopt-brace", "V", B, "shopt -s {dot,x}glob 2>/dev/null; cat *"),
    ("V-GLOBIGNORE-printf", "V", B, "printf -v GLOBIGNORE zz; cat *"),
    ("V-GLOBIGNORE-default", "V", B, ": ${GLOBIGNORE:=zz}; cat *"),
    ("V-GLOBIGNORE-indirect", "V", B, "n=GLOBIGNORE; declare $n=zz; cat *"),
    ("V-GLOBIGNORE-split-name", "V", B, "n=GLOB; declare ${n}IGNORE=zz; cat *"),
    ("V-GLOBIGNORE-split-printf", "V", B, "n=GLOB; printf -v ${n}IGNORE zz; cat *"),
    ("V-GLOBIGNORE-eval", "V", B, "eval GLOB''IGNORE=zz; cat *"),
    ("V-GLOBIGNORE-function", "V", B, "f() { GLOBIGNORE=zz; cat *; }; f"),
    ("V-bash-c", "V", B, "bash -c 'shopt -s dotglob; cat *'"),
    ("V-bash-c-args", "V", B, "bash -c 'shopt -s \"$1$2\"; cat *' x dot glob"),
    ("V-pipe-bash", "V", B, "echo 'shopt -s dotglob; cat *' | bash"),
    ("V-heredoc-bash", "V", B, "bash <<'X'\nshopt -s dotglob\ncat *\nX"),
    ("V-sh-O", "V", B, "sh -O dotglob -c 'cat *'"),
    ("V-bash-O-split", "V", B, "o=dot; bash -O ${o}glob -c 'cat *'"),
    ("V-env-BASHOPTS", "V", "bash5", "env BASHOPTS=dotglob {bash5} -c 'cat *'"),
    ("V-export-BASHOPTS", "V", "bash5", "export BASHOPTS=dotglob; {bash5} -c 'cat *'"),
    ("V-source-procsub", "V", B, "source <(echo shopt -s dotglob); cat *"),
    ("V-source-procsub-split", "V", B, "source <(echo shopt -s dot''glob); cat *"),
    ("V-setopt-nono", "V", "zsh", "setopt NO_NOGLOBDOTS; cat *"),
    ("V-setopt-localoptions", "V", "zsh", "() { setopt localoptions globdots; cat * }"),
    ("V-zsh-f-4-c", "V", "zsh", "zsh -f -4 -c 'cat *'"),
    ("V-set-e4", "V", "zsh", "set -e4; cat *"),
    ("V-unsetopt-plus4", "V", "zsh", "unsetopt +4; cat *"),
    ("V-emulate-ksh", "V", "zsh", "emulate ksh; cat *"),
    ("V-emulate-sh-o", "V", "zsh", "emulate sh -o globdots; cat *"),
    ("V-options-split", "V", "zsh", "o=glob; options[${o}dots]=on; cat *"),
    ("V-options-quoted", "V", "zsh", "options['glob''dots']=on; cat *"),
    ("V-setopt-split-var", "V", "zsh", "o=glob; setopt ${o}dots; cat *"),
    ("V-zsh-c-setopt", "V", "zsh", "zsh -c 'setopt globdots; cat *'"),
    ("V-glob-qual-D", "V", "zsh", "cat *(D.)"),
    ("V-glob-qual-hash-q", "V", "zsh+extendedglob", "cat *(#qD)"),
    ("V-dot-quoted", "V", B, "cat '.'*"),
    ("V-dot-escaped", "V", B, "cat \\.*"),
    ("V-dot-ansi", "V", B, "cat $'.'*"),
    ("V-dot-brace", "V", B, "cat {.,}*"),
    ("V-dot-brace-e", "V", B, "cat {x,.e}*"),
    ("V-dot-subst", "V", B, "cat $(printf .)*"),
    ("V-bracket-start", "V", B, "cat [.]*"),
    ("V-bracket-start-zsh", "V", "zsh", "cat [.]*"),
]
# G8 "auto": other must-blocks (the spec 2026-11-17). (id, mode spec, hook command, precondition
# command run for real (None: never run, check with printf), cwd, operand for printf check)
G8_OTHER = [
    ("H-grep-r-star-sub-env", B, "grep -r foo *", "grep -r SENTINEL_9f3c *", "proj/g8", None),
    ("H-rm-star-above-home", B, "rm -rf *", None, "..", "*"),
    ("H-var-dot-star", B, "x=.; cat $x*", "x=.; cat $x*", "proj/g8", None),
    ("H-zsh-qualifier-D", "zsh", "cat *(D)", "cat *(D)", "proj/g8", None),
]
# Reported, not asserted.
INFORMATIONAL = [  # SPEC section 3a "What it costs": denied, harmless, listed in the README
    ("zsh-group-dirs", "ls (src|tests)"),
    ("grep-caret-unquoted", "grep ^foo README.md"),
    ("echo-csharp", "echo C#"),
    ("double-bracket-pattern", "[[ $f == *.env ]] && echo y"),
    ("ls-dot-all", "ls .*"),
    # SPEC 3a "What it costs" under G7: denied although harmless.
    ("g7-cost-chmod-700-home", "chmod 700 ~"), ("g7-cost-grep-rm-home", "grep -r rm ~"),
    ("rg-recursive", "rg TODO ."),
    ("ls-dot-star", "ls .e*"),
    ("read-claude-settings", "cat ~/.claude/settings.json"),
]


# --- run ------------------------------------------------------------------------------------


def run(args) -> int:
    home = make_home()
    try:
        return _run(args, home)
    finally:
        if not args.keep:
            shutil.rmtree(home.parent, ignore_errors=True)
        else:
            print(f"fixture kept at {home}")


def _run(args, home: Path) -> int:
    modes = shell_modes()
    print("shells:")
    for v in shell_versions(modes):
        print("  " + v)
    print("modes: " + ", ".join(modes))
    if not modes:
        print("no shells found; nothing to check")
        return 2
    hook = Hook(args.hook, args.python, args.hook_takes_home, home)
    targets = protected_targets(home)
    failures: List[str] = []
    stats = {t: [0, 0] for t in ("NAMED", "GENERATED", "SENTINEL", "ANCESTOR", "G8", "MUST-ALLOW")}  # [passed, failed]
    print(f"G8 hidden_names setting under test: {HIDDEN[0]}")
    skips: List[str] = []
    strict = bool(args.require)
    needed = required_families(args.require)
    families = {name.split("+")[0] for name in modes}
    for need in needed:
        if need not in FAMILIES:
            print(f"  unknown shell family {need!r} in --require (use {', '.join(FAMILIES)} or auto)")
            return 2
        if need not in families:
            failures.append(f"REQUIRE shell {need!r} not available")
            print(f"  FAIL required shell {need} not available")
    for m in MODE_PROBLEMS:  # A25: a missing mode of a required shell is a failure
        if HIDDEN[0] == "auto" and ("dotglob" in m or "globdots" in m):
            continue  # G8 auto: these modes are not required (known miss 7); they still run if present
        if m.split("+")[0] in needed:
            failures.append(f"REQUIRE mode {m!r} could not be set up")
            print(f"  FAIL required mode {m} could not be set up")

    not_appl: List[str] = []

    def unavailable(tier: str, cid: str, spec: str) -> None:
        if strict:
            failures.append(f"{tier} {cid}: no shell mode for {spec!r} (A25: a missing mode is a failure)")
            stats[tier][1] += 1
            print(f"  FAIL {cid}: no mode for {spec}")
        else:
            skips.append(f"{tier} {cid}")
            print(f"  SKIP {cid}: no mode for {spec}")

    # Named cases: the stated mode must really reach the target, then the hook must deny.
    print("\n[NAMED] must-block, with precondition")
    for cid, spec, cmd, word, rel, cwd in NAMED:
        mode = resolve_mode(spec, modes)
        why = not_applicable(spec, modes)
        if why:
            not_appl.append(f"NAMED {cid} ({why})")
            print(f"  N/A  {cid}: {why}")
            continue
        if not mode:
            unavailable("NAMED", cid, spec)
            continue
        binary, setup = modes[mode]
        target = os.path.realpath(str(home / rel))
        got = reaches(expand(binary, setup, word, home, cwd), home, {target}, cwd)
        if not got:
            failures.append(f"NAMED {cid}: precondition failed, {mode} does not expand {word!r} to {rel}")
            stats["NAMED"][1] += 1
            print(f"  FAIL {cid}: precondition ({mode} does not reach {rel})")
            continue
        d = hook.decide(setup + cmd, cwd)
        if d == "deny":
            stats["NAMED"][0] += 1
            print(f"  ok   {cid} [{mode}] {cmd}")
        else:
            stats["NAMED"][1] += 1
            failures.append(f"NAMED {cid} [{mode}] {setup + cmd!r}: {d}")
            print(f"  FAIL {cid} [{mode}] {cmd}: {d}")

    # Generated words.
    rows = read_words(Path(args.words)) if args.words and Path(args.words).exists() and not args.quick else generate(args.quick)
    print(f"\n[GENERATED] {len(rows)} words x {len(modes)} modes")

    def one(row):
        label, cls, word, cmd, cwd = row
        res = []
        for mode, (binary, setup) in modes.items():
            try:
                got = reaches(expand(binary, setup, word, home, cwd), home, targets, cwd)
            except subprocess.TimeoutExpired:
                res.append(("ERR", mode, label, cls, cmd, "shell timed out"))
                continue
            if got:
                d = hook.decide(setup + cmd, cwd)
                res.append(("ok" if d == "deny" else "FAIL", mode, label, cls, cmd, d))
        return res

    with ThreadPoolExecutor(args.jobs) as ex:
        results = [r for rs in ex.map(one, rows) for r in rs]
    reached = len(results)
    gen_fail = [r for r in results if r[0] != "ok"]
    stats["GENERATED"] = [reached - len(gen_fail), len(gen_fail)]
    by_class: Dict[str, List] = {}
    for r in gen_fail:
        by_class.setdefault(r[3], []).append(r)
    print(f"  {reached} (word, mode) pairs reach a protected path; {len(gen_fail)} not denied")
    for cls, rs in sorted(by_class.items()):
        modes_hit = sorted({r[1] for r in rs})
        print(f"  FAIL class {cls!r}: {len(rs)} pairs, modes {modes_hit}; e.g. {rs[0][4]!r} -> {rs[0][5]}")
        failures += [f"GEN {r[1]} {r[2]} [{r[3]}] {r[4]!r}: {r[5]}" for r in rs]

    # Sentinel reads: really run (cat only), check the output.
    print("\n[SENTINEL] commands run for real (reads of fixture files only)")
    for cid, spec, cmd, cwd in SENTINEL_CASES:
        mode = resolve_mode(spec, modes)
        if not mode:
            unavailable("SENTINEL", cid, spec)
            continue
        binary, setup = modes[mode]
        r = subprocess.run([binary, "-c", setup + cmd], capture_output=True, text=True,
                           cwd=str(cwd_path(home, cwd)), env=env_for(home), stdin=subprocess.DEVNULL, timeout=TIMEOUT)
        if SENTINEL not in r.stdout:  # A25: a failed precondition is a failure
            failures.append(f"SENTINEL {cid}: precondition failed, {mode} did not read a protected file")
            stats["SENTINEL"][1] += 1
            print(f"  FAIL {cid}: precondition ({mode} did not read a protected file)")
            continue
        d = hook.decide(setup + cmd, cwd)
        if d == "deny":
            stats["SENTINEL"][0] += 1
            print(f"  ok   {cid} [{mode}] {cmd}")
        else:
            stats["SENTINEL"][1] += 1
            failures.append(f"SENTINEL {cid} [{mode}] {setup + cmd!r}: {d}")
            print(f"  FAIL {cid} [{mode}] {cmd}: {d}")

    # G7 ancestors: precondition = the operand resolves to home or above; nothing is run.
    print("\n[ANCESTOR] G7: delete, move or lock the home folder or above (never run)")
    home_real = os.path.realpath(str(home))
    for cid, spec, cmd, operand, cwd in ANCESTOR_CASES:
        if cid == "G7-cursor-delete-tool":
            event = {"cwd": str(home / "proj"), "hook_event_name": "preToolUse", "tool_name": "Delete",
                     "tool_input": {"path": str(home)}, "conversation_id": "oracle"}
            d = hook.decide("", "proj", event=event, agent="cursor")
            mode = "cursor"
        else:
            mode = resolve_mode(spec, modes)
            if not mode:
                unavailable("ANCESTOR", cid, spec)
                continue
            binary, setup = modes[mode]
            got = [os.path.realpath(os.path.join(str(cwd_path(home, cwd)), g))
                   for g in expand(binary, setup, operand, home, cwd)]
            if not any(home_real == g or home_real.startswith(g.rstrip(os.sep) + os.sep) for g in got):
                failures.append(f"ANCESTOR {cid}: precondition failed, {mode} does not resolve {operand!r} to home or above")
                stats["ANCESTOR"][1] += 1
                print(f"  FAIL {cid}: precondition ({operand!r} -> {got})")
                continue
            d = hook.decide(setup + cmd, cwd)
        if d == "deny":
            stats["ANCESTOR"][0] += 1
            print(f"  ok   {cid} [{mode}] {cmd}")
        else:
            stats["ANCESTOR"][1] += 1
            failures.append(f"ANCESTOR {cid} [{mode}] {cmd!r}: {d}")
            print(f"  FAIL {cid} [{mode}] {cmd}: {d}")

    # G8 hidden names.
    print(f"\n[G8] hidden names, setting {HIDDEN[0]}")
    g8_na: List[str] = []
    if HIDDEN[0] == "always":
        for c in G8_BARE_STAR:  # expected denies: with dotglob or globdots they reach .env
            d = hook.decide(c, G8_ALLOW_CWD)
            if d == "deny":
                stats["G8"][0] += 1
            else:
                stats["G8"][1] += 1
                failures.append(f"G8 always {c!r}: {d} (expected deny)")
                print(f"  FAIL always {c}: {d}")
    else:
        bash5 = _find_bashes().get("bash5", "")
        for cid, origin, spec, cmd in G8_SWITCH:
            mode = resolve_mode(spec, modes)
            if not mode or ("{bash5}" in cmd and not bash5):
                if origin == "H":
                    unavailable("G8", cid, spec)
                else:
                    g8_na.append(f"{cid} (no {spec})")
                continue
            cmd = cmd.replace("{bash5}", bash5)
            binary, setup = modes[mode]
            r = subprocess.run([binary, "-c", setup + cmd], capture_output=True, text=True,
                               cwd=str(cwd_path(home, "proj/g8")), env=env_for(home),
                               stdin=subprocess.DEVNULL, timeout=TIMEOUT)
            if SENTINEL not in r.stdout:
                if origin == "H":
                    failures.append(f"G8 {cid}: precondition failed, {mode} did not read a hidden file")
                    stats["G8"][1] += 1
                    print(f"  FAIL {cid}: precondition ({mode} did not read a hidden file)")
                else:
                    g8_na.append(f"{cid} (form does not reach a hidden file in {mode})")
                continue
            d = hook.decide(setup + cmd, "proj/g8")
            if d == "deny":
                stats["G8"][0] += 1
                print(f"  ok   {cid} [{mode}] {cmd!r}")
            else:
                stats["G8"][1] += 1
                failures.append(f"G8 {cid} [{mode}] {setup + cmd!r}: {d}")
                print(f"  FAIL {cid} [{mode}] {cmd!r}: {d}")
        home_real = os.path.realpath(str(home))
        for cid, spec, cmd, pre, cwd, operand in G8_OTHER:
            mode = resolve_mode(spec, modes)
            if not mode:
                unavailable("G8", cid, spec)
                continue
            binary, setup = modes[mode]
            if pre is not None:
                r = subprocess.run([binary, "-c", setup + pre], capture_output=True, text=True,
                                   cwd=str(cwd_path(home, cwd)), env=env_for(home), stdin=subprocess.DEVNULL, timeout=TIMEOUT)
                reached = SENTINEL in r.stdout
            else:
                got = [os.path.realpath(os.path.join(str(cwd_path(home, cwd)), x)) for x in expand(binary, setup, operand, home, cwd)]
                reached = any(home_real == x or home_real.startswith(x.rstrip(os.sep) + os.sep) for x in got)
            if not reached:
                failures.append(f"G8 {cid}: precondition failed in {mode}")
                stats["G8"][1] += 1
                print(f"  FAIL {cid}: precondition")
                continue
            d = hook.decide(setup + cmd, cwd)
            if d == "deny":
                stats["G8"][0] += 1
                print(f"  ok   {cid} [{mode}] {cmd!r}")
            else:
                stats["G8"][1] += 1
                failures.append(f"G8 {cid} [{mode}] {cmd!r}: {d}")
                print(f"  FAIL {cid} [{mode}] {cmd!r}: {d}")
        if g8_na:
            print("  attack forms that do not work here (not failures): " + "; ".join(g8_na))

    # Must-allow.
    print("\n[MUST-ALLOW] ordinary commands in a folder holding .env")
    allow_cases = [(cid, cmd, "proj") for cid, cmd in MUST_ALLOW]
    if HIDDEN[0] == "auto":
        allow_cases += [(cid, cmd, G8_ALLOW_CWD) for cid, cmd in AUTO_MUST_ALLOW]
    for cid, cmd, cwd in allow_cases:
        d = hook.decide(cmd, cwd)
        if d == "allow":
            stats["MUST-ALLOW"][0] += 1
        else:
            stats["MUST-ALLOW"][1] += 1
            failures.append(f"ALLOW {cid} {cmd!r}: {d}")
            print(f"  FAIL {cid}: {cmd}: {d[:140]}")
    print("\n[INFORMATIONAL] reported only")
    for cid, cmd in INFORMATIONAL:
        print(f"  {hook.decide(cmd)[:60]:<60} {cmd}")

    ok = sum(v[0] for v in stats.values())
    tiers = ", ".join(f"{t} {v[0]}/{v[0] + v[1]}" for t, v in stats.items())
    missing = sorted(m for m in ALL_MODE_NAMES if m not in modes)
    # Under --require, modes of a family this OS does not require are "not required here", not
    # skipped (bash3 exists only on macOS). Modes of a required family are failures, listed above.
    skipped_modes = [m for m in missing if not strict or m.split("+")[0] in needed]
    not_required = [m for m in missing if strict and m.split("+")[0] not in needed]
    print(f"\nRESULT: {ok} passed, {len(failures)} failed ({tiers}); skipped modes: "
          f"{', '.join(skipped_modes) or 'none'}; skipped cases: {len(skips)}; "
          f"not required on this OS: {', '.join(not_required) or 'none'}; not applicable: {len(not_appl)}")
    if skips:
        print("  skipped: " + "; ".join(skips))
    if not_appl:
        print("  not applicable: " + "; ".join(not_appl))
    LAST_STATS.clear()
    LAST_STATS.update({t: tuple(v) for t, v in stats.items()})
    if args.report:
        Path(args.report).write_text("\n".join(failures) + "\n", encoding="utf-8")
        print(f"failures written to {args.report}")
    return 1 if failures else 0


def self_test(args) -> int:
    """Controls: an allow-all hook must fail must-block; a deny-all hook must fail must-allow."""
    tmp = Path(tempfile.mkdtemp(prefix="denypeek-oracle-ctl-"))
    try:
        allow = tmp / "allow_all.py"
        allow.write_text("import sys; sys.stdin.read(); print('{}')\n")
        deny = tmp / "deny_all.py"
        deny.write_text("import sys, json; sys.stdin.read(); print(json.dumps({'hookSpecificOutput': "
                        "{'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', "
                        "'permissionDecisionReason': 'x'}}))\n")
        results, tiers = {}, {}
        for name, path in (("allow-all", allow), ("deny-all", deny)):
            ns = argparse.Namespace(**vars(args))
            ns.hook, ns.python, ns.hook_takes_home, ns.quick, ns.words, ns.report = str(path), sys.executable, False, True, None, None
            print(f"\n===== control: {name} =====")
            home = make_home()
            try:
                results[name] = _run_capture(ns, home)
                tiers[name] = dict(LAST_STATS)
            finally:
                shutil.rmtree(home.parent, ignore_errors=True)
        a, d = tiers.get("allow-all", {}), tiers.get("deny-all", {})
        block_tiers = ("NAMED", "GENERATED", "SENTINEL", "ANCESTOR", "G8")
        checks = {
            "allow-all fails every must-block tier": all(a.get(t, (0, 0))[0] == 0 and a.get(t, (0, 0))[1] > 0 for t in block_tiers),
            "allow-all passes must-allow": a.get("MUST-ALLOW", (0, 1))[1] == 0,
            "deny-all passes every must-block tier": all(d.get(t, (0, 1))[1] == 0 and d.get(t, (0, 0))[0] > 0 for t in block_tiers),
            "deny-all fails all of must-allow": d.get("MUST-ALLOW", (1, 0))[0] == 0,
        }
        for k, v in checks.items():
            print(f"  {'ok  ' if v else 'FAIL'} {k}")
        good = all(checks.values()) and results["allow-all"] == 1 and results["deny-all"] == 1
        print(f"\nSELF-TEST: {'PASS' if good else 'FAIL'}")
        return 0 if good else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _run_capture(ns, home):
    return _run(ns, home)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hook", help="guard.py, or an executable hook command")
    ap.add_argument("--python", default="/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable,
                    help="Python to run a guard.py hook with (default /usr/bin/python3)")
    ap.add_argument("--hook-takes-home", action="store_true", help="pass --home <fixture> to a non-.py hook")
    ap.add_argument("--words", default=str(HERE / "words.tsv"), help="word list (default: words.tsv next to this script)")
    ap.add_argument("--quick", action="store_true", help="one word per mutation class instead of the word list")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--require", help="comma list of shell families that must be present (bash3, bash5, zsh, sh), "
                    "or 'auto' (macOS: all four; elsewhere: bash5, zsh, sh). With it, a missing shell, mode or "
                    "named case fails the run (A25)")
    ap.add_argument("--report", help="write every failure to this file")
    ap.add_argument("--keep", action="store_true", help="keep the fixture home")
    ap.add_argument("--hidden", choices=("always", "auto"), default="always",
                    help="SPEC 3a G8 setting written to the fixture's guard-state.json (default always)")
    ap.add_argument("--self-test", action="store_true", help="run the allow-all and deny-all controls")
    ap.add_argument("--write-words", help="write the generated word list to this file and exit")
    args = ap.parse_args(argv)
    HIDDEN[0] = args.hidden
    if args.write_words:
        rows = generate()
        write_words(Path(args.write_words), rows)
        print(f"wrote {len(rows)} words to {args.write_words}")
        return 0
    if args.self_test:
        return self_test(args)
    if not args.hook or not os.path.exists(args.hook):
        ap.error("--hook PATH is required and must exist")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
