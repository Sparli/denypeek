#!/usr/bin/env python3
"""keyhush guard: a pre-tool hook that stops coding agents reading secret files.

One file, Python 3.9+ standard library only. `keyhush guard install` copies it to
~/.keyhush/guard.py and wires it into each agent:

    python3 ~/.keyhush/guard.py --agent claude|codex|cursor|gemini

It reads the agent's hook JSON on stdin and denies:
- file reads, edits and writes of a path that matches ~/.keyhush/secretfiles;
- shell commands that name such a path (after quotes, ~, $HOME, $IFS and globs);
- recursive grep (or ripgrep) over a folder that holds such a file.
Anything else is allowed. On any error of its own it blocks (fails closed) and says how to
remove it: keyhush guard uninstall.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import shlex
import sys
import time

GUARD_VERSION = "0.1.0"
MAX_INPUT = 4_000_000  # bytes; bigger hook inputs are blocked, not parsed
WALK_LIMIT = 20_000  # entries checked when a grep targets a folder
WALK_SECONDS = 0.4
UNINSTALL = "keyhush guard uninstall"

DEFAULT_PATTERNS = """\
# keyhush secret files: gitignore-style patterns, one per line. Case does not matter.
# A name with no slash matches at any depth. `~/` is your home folder.
# A line starting with ! allows a path again. Edit, then run: keyhush guard test
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
!*.pub
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
"""

AGENTS = ("claude", "codex", "cursor", "gemini")
SHELL_KEYS = ("command", "cmd", "script")
GREP_TOOLS = {"Grep", "grep_search", "search_file_content"}
SHELL_OPERATORS = re.compile(r"\|\||&&|;|\||&|\n|\(|\)|`|\$\(")
GREP_NAMES = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "git"}


# --- patterns ------------------------------------------------------------------------


def home_dir():
    return os.path.expanduser("~")


def load_patterns(path=None):
    path = path or os.path.join(home_dir(), ".keyhush", "secretfiles")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        text = DEFAULT_PATTERNS
    return parse_patterns(text)


def parse_patterns(text):
    """Return a list of (negate, pattern, matcher) with the matcher compiled once."""
    rules = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        if negate:
            line = line[1:].strip()
        if line:
            rules.append((negate, line, compile_pattern(line)))
    return rules


def _norm(path):
    return path.replace("\\", "/").lower()


def _glob_to_re(pat):
    """gitignore-style glob to regex over a '/'-separated, lower-case path."""
    i, out = 0, []
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pat[i + 1 : j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def compile_pattern(pat):
    """Return a function(path) -> bool. path is absolute and normalised by _norm."""
    p = _norm(pat)
    dir_only = p.endswith("/")
    p = p.rstrip("/")
    if p.startswith("~/"):
        home = _norm(home_dir()).rstrip("/")
        rx = re.compile("^" + re.escape(home) + "/" + _glob_to_re(p[2:]) + "(?:/.*)?$")
        return lambda path: bool(rx.match(path))
    if p.startswith("/") or re.match(r"^[a-z]:/", p):
        rx = re.compile("^" + _glob_to_re(p) + "(?:/.*)?$")
        return lambda path: bool(rx.match(path))
    if "/" in p:
        rx = re.compile("(?:^|/)" + _glob_to_re(p) + "(?:/.*)?$")
        return lambda path: bool(rx.search(path))
    name = re.compile("^" + _glob_to_re(p) + "$")

    def by_name(path):
        parts = [x for x in path.split("/") if x]
        if dir_only:
            parts = parts[:-1]
        return any(name.match(part) for part in parts)

    return by_name


def is_secret(path, rules):
    """True if this path is a secret file (last matching pattern wins, like gitignore)."""
    candidates = {_norm(path)}
    try:
        candidates.add(_norm(os.path.realpath(path)))
    except (OSError, ValueError):
        pass
    for cand in candidates:
        verdict = False
        for negate, _pat, matches in rules:
            if matches(cand):
                verdict = not negate
        if verdict:
            return True
    return False


# --- resolving paths in tool input ---------------------------------------------------


def expand(token, cwd):
    t = token.strip().strip("'\"")
    if not t:
        return None
    home = home_dir()
    for var in ("${HOME}", "$HOME"):
        t = t.replace(var, home)
    if t.startswith("~"):
        t = os.path.expanduser(t)
    if not os.path.isabs(t) and not re.match(r"^[A-Za-z]:[\\/]", t):
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


def path_hits(token, cwd, rules):
    """Paths named by one token, including glob expansion. Returns the secret ones."""
    full = expand(token, cwd)
    if not full:
        return []
    found = []
    if is_secret(full, rules):
        found.append(full)
    if any(ch in token for ch in "*?["):
        candidates = []
        try:
            candidates += glob.glob(full)
        except (OSError, re.error):
            pass
        # glob skips hidden files for `*`; check names in the folder directly too.
        folder, pattern = os.path.split(full)
        try:
            names = os.listdir(folder) if not any(ch in folder for ch in "*?[") else []
        except OSError:
            names = []
        candidates += [os.path.join(folder, n) for n in names
                       if fnmatch.fnmatchcase(n.lower(), pattern.lower())]
        found += [c for c in candidates if is_secret(c, rules)]
    return found


def folder_holds_secret(folder, rules, deadline):
    """True if the folder (recursively) holds a secret file. Raises TimeoutError if too big."""
    seen = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
        for name in filenames + dirnames:
            seen += 1
            if seen > WALK_LIMIT or time.monotonic() > deadline:
                raise TimeoutError
            if is_secret(os.path.join(dirpath, name), rules):
                return True
    return False


def split_tokens(command):
    """Shell-ish tokens. Splits on operators, quotes and $IFS tricks. Never runs anything."""
    text = command.replace("${IFS}", " ").replace("$IFS", " ")
    text = re.sub(r"[<>]+&?\d*", " ", text)  # redirections: cat<.env, >out
    tokens = []
    for part in SHELL_OPERATORS.split(text):
        try:
            words = shlex.split(part, posix=True)
        except ValueError:
            words = part.split()
        for w in words:
            tokens.append(w)
            if "=" in w and not w.startswith("="):  # --file=.env, VAR=.env
                tokens.append(w.split("=", 1)[1])
    return tokens, [t for t in SHELL_OPERATORS.split(text)]


def grep_targets(part, cwd):
    """If this command segment is a recursive grep, return the folders it searches."""
    try:
        words = shlex.split(part, posix=True)
    except ValueError:
        words = part.split()
    while words and ("=" in words[0] and not words[0].startswith("-")):
        words = words[1:]  # leading VAR=value
    if not words:
        return []
    prog = os.path.basename(words[0]).lower()
    args = words[1:]
    if prog == "git":
        if not args or args[0] != "grep":
            return []
        prog, args = "git-grep", args[1:]
    if prog not in GREP_NAMES and prog != "git-grep":
        return []
    recursive = prog in ("rg", "ag", "ack", "git-grep") or any(
        a in ("-r", "-R", "--recursive", "--dereference-recursive")
        or (a.startswith("-") and not a.startswith("--") and ("r" in a[1:] or "R" in a[1:]))
        for a in args
    )
    if not recursive:
        return []
    positional = [a for a in args if not a.startswith("-")]
    paths = positional[1:] if prog not in ("git-grep",) else positional[1:]
    if not paths:
        paths = ["."]
    out = []
    for p in paths:
        full = expand(p, cwd)
        if full and os.path.isdir(full):
            out.append(full)
    return out


def check_command(command, cwd, rules, deadline):
    tokens, parts = split_tokens(command)
    for tok in tokens:
        hits = path_hits(tok, cwd, rules)
        if hits:
            return f"the command names a secret file ({os.path.basename(hits[0])})"
    for part in parts:
        for folder in grep_targets(part, cwd):
            try:
                if folder_holds_secret(folder, rules, deadline):
                    return f"recursive search over {folder}, which holds a secret file"
            except TimeoutError:
                return f"recursive search over {folder}: too many files to check; narrow the path"
    return None


def patch_paths(text):
    out = []
    for line in text.splitlines():
        for prefix in ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "):
            if line.startswith(prefix):
                out.append(line[len(prefix):].strip())
    return out


def strings_in(value, key=None):
    """Every (key, string) pair in a JSON value."""
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from strings_in(v, k)
    elif isinstance(value, list):
        if key in SHELL_KEYS and value and all(isinstance(x, str) for x in value):
            yield key, " ".join(shlex.quote(x) for x in value)
            return
        for v in value:
            yield from strings_in(v, key)


def decide(event, rules):
    """Return a reason string to deny, or None to allow."""
    deadline = time.monotonic() + WALK_SECONDS
    cwd = event.get("cwd") or (event.get("tool_input") or {}).get("working_directory") \
        or (event.get("tool_input") or {}).get("dir_path") or os.getcwd()
    if isinstance(event.get("workspace_roots"), list) and not event.get("cwd"):
        roots = [r for r in event["workspace_roots"] if isinstance(r, str)]
        cwd = roots[0] if roots else cwd
    tool = event.get("tool_name") or ""
    tool_input = event.get("tool_input")
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            pass
    scope = {"tool_input": tool_input} if tool_input is not None else {
        k: v for k, v in event.items() if k in ("file_path", "command", "attachments")
    }
    for key, s in strings_in(scope):
        if len(s) > 100_000:
            continue
        if key in SHELL_KEYS:
            if tool == "apply_patch" or s.lstrip().startswith("*** Begin Patch"):
                for p in patch_paths(s):
                    if path_hits(p, cwd, rules):
                        return f"the patch edits a secret file ({os.path.basename(p)})"
                continue
            reason = check_command(s, cwd, rules, deadline)
            if reason:
                return reason
            continue
        if not s or "\n" in s or len(s) > 4096:
            continue
        if path_hits(s, cwd, rules):
            return f"{os.path.basename(s.rstrip('/'))} is a secret file"
        if tool in GREP_TOOLS and key in ("path", "dir_path"):
            folder = expand(s, cwd)
            if folder and os.path.isdir(folder):
                try:
                    if folder_holds_secret(folder, rules, deadline):
                        return f"search over {folder}, which holds a secret file; narrow the path"
                except TimeoutError:
                    return f"search over {folder}: too many files to check; narrow the path"
    if tool in GREP_TOOLS and isinstance(tool_input, dict) and not (
        tool_input.get("path") or tool_input.get("dir_path")
    ):
        try:
            if folder_holds_secret(cwd, rules, deadline):
                return f"search over {cwd}, which holds a secret file; narrow the path"
        except TimeoutError:
            return f"search over {cwd}: too many files to check; narrow the path"
    return None


# --- agent formats -------------------------------------------------------------------


def deny_output(agent, event_name, reason):
    """(stdout, exit code) that each agent reads as a denial."""
    msg = f"keyhush blocked this: {reason}. If this is wrong, edit ~/.keyhush/secretfiles."
    if agent == "cursor":
        return json.dumps({"permission": "deny", "user_message": msg, "agent_message": msg}), 0
    if agent == "gemini":
        return json.dumps({"decision": "deny", "reason": msg}), 0
    # claude and codex share this shape
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": event_name or "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": msg,
    }}), 0


def allow_output(agent):
    """Allow without approving: defer to the agent's own permission prompts."""
    if agent == "cursor":
        return json.dumps({"permission": "allow"}), 0  # Cursor blocks on empty output
    return "", 0


def fail_closed(agent, why):
    msg = f"keyhush guard error ({why}); blocked to be safe. To remove the guard: {UNINSTALL}"
    out, _ = deny_output(agent, "PreToolUse", why)
    data = json.loads(out)
    for k in ("user_message", "agent_message", "reason"):
        if k in data:
            data[k] = msg
    if "hookSpecificOutput" in data:
        data["hookSpecificOutput"]["permissionDecisionReason"] = msg
    return json.dumps(data), 2, msg


def run(argv, stdin_bytes):
    agent = "claude"
    if "--agent" in argv:
        i = argv.index("--agent")
        if i + 1 < len(argv):
            agent = argv[i + 1]
    if agent not in AGENTS:
        return fail_closed("claude", f"unknown agent {agent!r}")
    if len(stdin_bytes) > MAX_INPUT:
        return fail_closed(agent, "hook input too large to check")
    if not stdin_bytes.strip():
        return fail_closed(agent, "empty hook input")
    try:
        event = json.loads(stdin_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return fail_closed(agent, "hook input is not valid JSON")
    if not isinstance(event, dict):
        return fail_closed(agent, "hook input is not a JSON object")
    rules = load_patterns()
    reason = decide(event, rules)
    if reason:
        out, code = deny_output(agent, event.get("hook_event_name"), reason)
        return out, code, reason
    out, code = allow_output(agent)
    return out, code, ""


def main():
    agent = "claude"
    try:
        if "--agent" in sys.argv:
            agent = sys.argv[sys.argv.index("--agent") + 1]
        data = sys.stdin.buffer.read(MAX_INPUT + 1)
        out, code, msg = run(sys.argv[1:], data)
    except BaseException as exc:  # fail closed on anything
        out, code, msg = fail_closed(agent if agent in AGENTS else "claude", type(exc).__name__)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if code == 2 and msg:
        sys.stderr.write(msg + "\n")
    sys.exit(code)


if __name__ == "__main__":
    main()
