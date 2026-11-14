#!/usr/bin/env python3
"""denypeek guard: a pre-tool hook that stops coding agents reading secret files.

One file, Python 3.9+ standard library only. `denypeek guard install` copies it to
~/.denypeek/guard.py and wires it into each agent:

    python3 ~/.denypeek/guard.py --agent claude|codex|cursor|gemini

It reads the agent's hook JSON on stdin and denies:
- file reads, edits and writes of a path that matches ~/.denypeek/secretfiles;
- shell commands that name such a path (after quotes, ~, $HOME, $IFS and globs);
- recursive grep (or ripgrep) over a folder that holds such a file.
Anything else is allowed. On any error of its own it blocks (fails closed) and says how to
remove it: denypeek guard uninstall.
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
import unicodedata

GUARD_VERSION = "0.1.0"
HOOK_SECONDS = 2.5  # the whole decision; past this the call is denied (agents wait about 10 s)
MAX_TOKENS = 5000  # words in one shell command
MAX_GLOB_RESULTS = 2000  # paths one glob may expand to
_deadline = [float("inf")]


WORKDIR_KEYS = ("workdir", "dir_path", "directory", "working_directory", "cwd")
MAX_COMMAND = 100_000  # characters in one shell command; longer ones are denied
MAX_PATH = 4096  # characters in one path; longer ones are denied
PATH_KEY_PARTS = ("path", "file", "dir", "include", "target", "source", "destination")


def is_path_key(key):
    """Field names that hold paths in the agents' tool inputs (file_path, dir_path, paths...)."""
    k = (key or "").lower()
    return any(part in k for part in PATH_KEY_PARTS)


class HookTimeout(Exception):
    """The hook ran out of time; the call is denied."""


def tick():
    # >=, not >: on Windows with Python 3.12 the monotonic clock moves in ~15.6 ms steps, so a
    # deadline that has been reached must count as passed even if the clock has not ticked.
    if time.monotonic() >= _deadline[0]:
        raise HookTimeout("took too long to check")


MAX_INPUT = 4_000_000  # bytes; bigger hook inputs are blocked, not parsed
WALK_LIMIT = 20_000  # entries checked when a grep targets a folder
WALK_SECONDS = 0.4
UNINSTALL = "denypeek guard uninstall"

DEFAULT_PATTERNS = """\
# denypeek secret files: gitignore-style patterns, one per line. Case does not matter.
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
MANY_FILE_TOOLS = {"read_many_files"}
SHELL_OPERATORS = re.compile(r"\|\||&&|;|\||&|\n|\(|\)|`|\$\(")
GREP_NAMES = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "git"}


# --- patterns ------------------------------------------------------------------------


_home = [None]  # set from --home, which `guard install` writes into the hook command


def home_dir():
    """The user's real home folder: from --home, else the system account record.

    Never from the HOME variable, which an agent may be able to set for the hook (R1).
    Windows has no account record in the standard library, so there USERPROFILE is used.
    """
    if _home[0]:
        return _home[0]
    if os.name == "posix":
        try:
            import pwd

            return pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError):
            pass
    return os.path.expanduser("~")


def load_patterns(path=None):
    path = path or os.path.join(home_dir(), ".denypeek", "secretfiles")
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


def _bracket_end(pat, i):
    """Index just past the shell bracket expression starting at pat[i] == "[", or -1.

    Follows bash, zsh and sh: an optional `!` or `^`, then a `]` right after it is a member,
    `[:class:]`, `[=c=]` and `[.c.]` hold their own `]`, and a `/` ends the attempt (the `[`
    is then literal)."""
    j = i + 1
    if j < len(pat) and pat[j] in "!^":
        j += 1
    if j < len(pat) and pat[j] == "]":
        j += 1
    while j < len(pat):
        c = pat[j]
        if c == "/":
            return -1
        if c == "[" and j + 1 < len(pat) and pat[j + 1] in ":=.":
            close = pat.find(pat[j + 1] + "]", j + 2)
            if close != -1:
                j = close + 2
                continue
        if c == "]":
            return j + 1
        j += 1
    return -1


def shell_glob(pattern):
    """A Python glob that matches at least everything the shell glob can (L1, L2).

    Every bracket expression becomes `?`, and so does a `[` with no closing `]` (the shell
    reads it as a literal `[`, which `?` also matches). Python then never sees `[`: its fnmatch
    reads `[^x]` as a literal `^` or `x`, and Python 3.9 raises on `[z-a]`. This can only make
    the guard block more, never less."""
    out, i = [], 0
    while i < len(pattern):
        if pattern[i] == "[":
            end = _bracket_end(pattern, i)
            out.append("?")
            i = end if end != -1 else i + 1
        else:
            out.append(pattern[i])
            i += 1
    return "".join(out)


def name_matches(name, pattern):
    """Shell glob match of one name, ignoring case, as a superset of what the shell matches.
    A pattern that still fails to compile counts as a match, so the guard blocks."""
    try:
        return fnmatch.fnmatchcase(name.lower(), shell_glob(pattern).lower())
    except re.error:
        return True


def _norm(path):
    return unicodedata.normalize("NFC", path).replace("\\", "/").lower()


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


# --- self-protection -------------------------------------------------------------------
# An agent must not be able to switch the guard off. denypeek's own folder and the files that
# hold the agents' hook settings are always denied, whatever the pattern list says. The user
# changes them in their own terminal, where no hook runs.


def protected_paths():
    """(denypeek folder, set of protected files), normalised. Includes symlink targets."""
    home = home_dir()
    claude_dirs = {os.path.join(home, ".claude")}
    codex_dirs = {os.path.join(home, ".codex")}
    if os.environ.get("CLAUDE_CONFIG_DIR"):
        claude_dirs.add(os.environ["CLAUDE_CONFIG_DIR"])
    if os.environ.get("CODEX_HOME"):
        codex_dirs.add(os.environ["CODEX_HOME"])
    files = [os.path.join(d, "settings.json") for d in claude_dirs]
    files += [os.path.join(d, "hooks.json") for d in codex_dirs]
    # `[features] hooks = false` in config.toml turns Codex hooks off
    files += [os.path.join(d, "config.toml") for d in codex_dirs]
    files += [
        os.path.join(home, ".cursor", "hooks.json"),
        os.path.join(home, ".gemini", "settings.json"),
    ]
    norm = set()
    for f in files:
        norm.add(_norm(os.path.normpath(f)))
        try:
            norm.add(_norm(os.path.realpath(f)))
        except (OSError, ValueError):
            pass
    kdir = os.path.join(home, ".denypeek")
    dirs = {_norm(os.path.normpath(kdir))}
    # Per-user Python folders: a usercustomize.py, sitecustomize.py or .pth file there runs
    # before any script in Pythons that load the user site (G1).
    for d in python_user_dirs(home):
        dirs.add(_norm(os.path.normpath(d)))
    try:
        dirs.add(_norm(os.path.realpath(kdir)))
    except (OSError, ValueError):
        pass
    return dirs, norm


def python_user_dirs(home):
    """User site folders for every Python version: macOS framework, POSIX and Windows."""
    out = [os.path.join(home, "Library", "Python")]
    local_lib = os.path.join(home, ".local", "lib")
    try:
        out += [
            os.path.join(local_lib, n)
            for n in os.listdir(local_lib)
            if n.lower().startswith("python")
        ]
    except OSError:
        pass
    appdata = os.environ.get("APPDATA")
    if appdata:
        out.append(os.path.join(appdata, "Python"))
    return out


def _python_user_file(path):
    """True for ~/.local/lib/pythonX.Y/... even if that folder does not exist yet."""
    p = _norm(path)
    home = _norm(home_dir()).rstrip("/")
    return bool(re.match(re.escape(home) + r"/\.local/lib/python[0-9.]*(?:/|$)", p))


def is_protected(path):
    dirs, files = protected_paths()
    candidates = {_norm(path)}
    try:
        candidates.add(_norm(os.path.realpath(path)))
    except (OSError, ValueError):
        pass
    for cand in candidates:
        if cand in files or _python_user_file(cand):
            return True
        if any(cand == d or cand.startswith(d + "/") for d in dirs):
            return True
    return False


# Settings that switch every hook off, so the guard with them. A project's own
# .claude/settings.json can set disableAllHooks over the user's settings (Claude Code hooks
# docs), and `[features] hooks = false` in any Codex config.toml turns Codex hooks off.
# [+ \t]*, not [+\s]*: \s crosses newlines and made this quadratic in line count (G2).
OFF_SWITCH = re.compile(
    r"disableAllHooks|^[+ \t]*(?:codex_)?hooks[ \t]*=[ \t]*false\b", re.I | re.M
)


JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def switches_hooks_off(text):
    if OFF_SWITCH.search(text):
        return True
    # A JSON file decodes \u0041 to A, so check the unescaped text as well (R2).
    if "\\u" in text:
        decoded = JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
        return bool(OFF_SWITCH.search(decoded))
    return False


# --- agent settings files anywhere (G5) ---------------------------------------------------
# The user-level files above are always denied. The same files inside a project can also turn
# hooks off, so edits to them are checked by parsing what the file would contain afterwards.
SETTINGS_NAMES = {
    ".claude/settings.json": "claude",
    ".claude/settings.local.json": "claude",
    ".codex/config.toml": "codex",
    ".codex/hooks.json": "json",
    ".gemini/settings.json": "gemini",
    ".cursor/hooks.json": "json",
}
HOOK_ENV_NAMES = {
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "PATH",
    "DEVELOPER_DIR",
    "SDKROOT",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "SHELL",
    "BASH_ENV",
    "ENV",
    # shell variables that change how a shell runs the hook command (F1)
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "PROMPT_COMMAND",
    "PS4",
    "ZDOTDIR",
}
READ_VERBS = {
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "jq",
    "wc",
    "ls",
    "stat",
    "file",
    "diff",
    "bat",
    "git",
    "nl",
    "od",
    "xxd",
    "sha256sum",
    "shasum",
    "md5",
    "md5sum",
    "type",
    "get-content",
    "gc",
}
REDIRECT_TARGET = re.compile(r">{1,2}\|?\s*([^\s;|&<>]+)")


def settings_kind(path):
    p = _norm(path)
    for name, kind in SETTINGS_NAMES.items():
        if p.endswith("/" + name) or p == name:
            return kind
    return None


def _strip_json_comments(text):
    """Remove // and /* */ comments outside strings (Gemini allows them in settings.json)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _find_key(value, key):
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key and v:
                return True
            if _find_key(v, key):
                return True
    elif isinstance(value, list):
        return any(_find_key(v, key) for v in value)
    return False


def settings_problem(kind, text):
    """Why this settings content would switch hooks off or cannot be checked, or None."""
    off = "the change would switch agent hooks off, which would disable denypeek"
    if kind == "codex":
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            tomllib = None
        if tomllib is None:
            if re.search(
                r"(?im)^[ \t]*(features[ \t]*\.[ \t]*)?(codex_)?hooks[ \t]*=[ \t]*false"
                r"|features[ \t]*=[ \t]*\{[^}]*hooks[ \t]*=[ \t]*false",
                text,
            ):
                return off
            return None
        try:
            data = tomllib.loads(text)
        except (ValueError, TypeError):
            return "the new config.toml cannot be parsed, so it cannot be checked"
        features = data.get("features") if isinstance(data, dict) else None
        if isinstance(features, dict) and (
            features.get("hooks") is False or features.get("codex_hooks") is False
        ):
            return off
        return None
    try:
        data = json.loads(_strip_json_comments(text) if kind == "gemini" else text)
    except ValueError:
        return "the new settings file cannot be parsed, so it cannot be checked"
    if kind == "claude" and _find_key(data, "disableAllHooks"):
        return off
    if kind == "claude" and isinstance(data, dict) and isinstance(data.get("env"), dict):
        # A settings env block may reach the hook process (R1); these change what it runs.
        risky = [
            k
            for k in data["env"]
            if str(k).upper() in HOOK_ENV_NAMES
            or str(k).upper().startswith(("PYTHON", "BASH_FUNC_"))
        ]
        if risky:
            return (
                "the change would set "
                + ", ".join(sorted(map(str, risky)))
                + " for the agent, which could change how the denypeek hook runs"
            )
    if kind == "gemini" and isinstance(data, dict):
        cfg = data.get("hooksConfig")
        if isinstance(cfg, dict):
            if cfg.get("enabled") is False:
                return off
            disabled = cfg.get("disabled")
            if isinstance(disabled, list) and any("denypeek" in str(x).lower() for x in disabled):
                return off
    return None


def settings_edit_problem(path, tool_input):
    """For a tool call naming a project settings file: check the content it would leave."""
    kind = settings_kind(path)
    if not kind or not isinstance(tool_input, dict):
        return None
    if isinstance(tool_input.get("content"), str):
        return settings_problem(kind, tool_input["content"])
    if isinstance(tool_input.get("new_string"), str):
        try:
            if os.path.getsize(path) > 1_000_000:
                return "the settings file is too big to check"
            with open(path, encoding="utf-8") as fh:
                current = fh.read()
        except FileNotFoundError:
            current = ""
        except (OSError, UnicodeDecodeError):
            return "the settings file cannot be read, so the edit cannot be checked"
        old = tool_input.get("old_string") or ""
        new = tool_input["new_string"]
        if old and old not in current:
            return None  # the edit tool will refuse it
        result = (
            current.replace(old, new)
            if tool_input.get("replace_all")
            else current.replace(old, new, 1)
            if old
            else new
        )
        return settings_problem(kind, result)
    return None  # a read


def patch_settings_problem(text, cwd):
    """Codex apply_patch on a project settings file: Add File is checked, others denied."""
    current, header, lines = None, None, []

    def finish():
        if current is None:
            return None
        if header == "add":
            return settings_problem(settings_kind(current), "\n".join(lines) + "\n")
        return (
            "a patch changes an agent settings file, which denypeek cannot check; "
            "edit it in your own terminal"
        )

    for line in text.splitlines():
        if line.startswith("*** "):
            problem = finish()
            if problem:
                return problem
            current, header, lines = None, None, []
            for prefix, kind in (
                ("*** Add File: ", "add"),
                ("*** Update File: ", "update"),
                ("*** Delete File: ", "delete"),
                ("*** Move to: ", "move"),
            ):
                if line.startswith(prefix):
                    path = expand(line[len(prefix) :].strip(), cwd) or ""
                    if settings_kind(path):
                        current, header = path, kind
        elif current is not None and header == "add" and line.startswith("+"):
            lines.append(line[1:])
    return finish()


AGENT_FOLDER_NAMES = {".claude", ".codex", ".gemini", ".cursor"}
GIT_READ = {
    "status",
    "log",
    "diff",
    "show",
    "grep",
    "ls-files",
    "blame",
    "rev-parse",
    "cat-file",
    "describe",
    "shortlog",
    "whatchanged",
    "ls-tree",
}
IN_PLACE_EDITORS = {"sed", "gsed", "perl", "ruby"}


def is_agent_folder(path):
    """A project-level (or user-level) agent settings folder itself, such as proj/.claude."""
    return (
        bool(path)
        and os.path.basename(_norm(os.path.normpath(path)).rstrip("/")) in AGENT_FOLDER_NAMES
    )


def shell_settings_problem(command, folders):
    """Shell commands may read agent settings files but not write them, and may not use an
    agent settings folder itself as the source or target of a change (R2): `cp x .claude/`,
    `mv dir .claude`, `tar -C .claude`, `dd of=.claude/settings.json`."""
    for raw in SHELL_OPERATORS.split(command):
        for target in REDIRECT_TARGET.findall(raw):
            if any(settings_kind(expand(target, f) or "") for f in folders):
                return "the command writes an agent settings file; edit it in your own terminal"
        text = REDIRECT_TARGET.sub(" ", raw)
        try:
            words = shlex.split(text, posix=True)
        except ValueError:
            words = text.split()
        while words and "=" in words[0] and not words[0].startswith("-"):
            words = words[1:]
        if not words:
            continue
        args = []
        for w in words[1:]:
            args.append(w)
            if "=" in w:  # dd of=..., --target-directory=...
                args.append(w.split("=", 1)[1])
        files = [w for w in args if any(settings_kind(expand(w, f) or "") for f in folders)]
        dirs = [w for w in args if any(is_agent_folder(expand(w, f)) for f in folders)]
        if not files and not dirs:
            continue
        verb = os.path.basename(words[0]).lower()
        if verb == "git":
            sub = next((w for w in words[1:] if not w.startswith("-")), "")
            read_only = sub in GIT_READ
        else:
            folder_only = bool(dirs) and not files
            read_only = verb in READ_VERBS or (
                folder_only
                and (verb == "mkdir" or verb in DIR_READ_VERBS)
                and not (verb == "find" and FIND_ACTIONS & set(words))
            )
        if verb in IN_PLACE_EDITORS and any(w.startswith("-i") or w == "--in-place" for w in words):
            read_only = False
        if not read_only:
            return (
                "the command may change an agent settings file or folder; "
                "edit it in your own terminal"
            )
    return None


# --- the agent folders that hold the hook settings (QA pass 2) -------------------------
# Moving, deleting or rewriting ~/.claude (and friends) removes the hook with it, so shell
# commands that name one of these folders may only read it.
DIR_READ_VERBS = READ_VERBS | {
    "du",
    "tree",
    "cd",
    "pushd",
    "find",
    "echo",
    "open",
    "realpath",
    "readlink",
    "dirname",
    "basename",
    "test",
    "[",
}
FIND_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"}


def agent_dirs():
    home = home_dir()
    dirs = [os.path.join(home, n) for n in (".claude", ".codex", ".cursor", ".gemini")]
    for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        if os.environ.get(var):
            dirs.append(os.environ[var])
    out = set()
    for d in dirs:
        out.add(_norm(os.path.normpath(d)).rstrip("/"))
        try:
            out.add(_norm(os.path.realpath(d)).rstrip("/"))
        except (OSError, ValueError):
            pass
    return out


def is_agent_dir(path):
    return bool(path) and _norm(os.path.normpath(path)).rstrip("/") in agent_dirs()


def _names_agent_dir(word, folders):
    """True if the word, after braces and globs, names an agent settings folder (R3)."""
    for variant in expand_braces(word):
        for f in folders:
            full = expand(variant, f)
            if not full:
                continue
            if is_agent_dir(full):
                return True
            if any(ch in variant for ch in "*?["):
                try:
                    pat = expand(variant, f, True)
                    for n, match in enumerate(glob.iglob(pat, recursive=True)):
                        tick()
                        if n >= MAX_GLOB_RESULTS:
                            raise HookTimeout("a glob matches too many files to check")
                        if is_agent_dir(match):
                            return True
                except (OSError, re.error):
                    pass
                folder, pattern = os.path.split(full)
                try:
                    literal_folder = not any(c in os.path.dirname(variant) for c in "*?[")
                    names = os.listdir(folder) if literal_folder else []
                except OSError:
                    names = []
                for n in names:  # glob skips hidden names for a leading *
                    if name_matches(n, pattern) and is_agent_dir(os.path.join(folder, n)):
                        return True
    return False


def _find_reaches_agent_dir(words, folders):
    """find with -delete or -exec, starting at the home folder or above an agent folder."""
    starts = []
    for w in words[1:]:
        if w.startswith("-") or w in ("!", "(", ")"):
            break
        starts.append(w)
    starts = starts or ["."]
    dirs = agent_dirs()
    for st in starts:
        for f in folders:
            full = expand(st, f)
            if not full:
                continue
            root = _norm(os.path.normpath(full)).rstrip("/")
            if any(d == root or d.startswith(root + "/") for d in dirs):
                return True
    return False


def shell_folder_problem(command, folders):
    message = (
        "the command may move, delete or change an agent's settings folder, which "
        "would remove the denypeek hook; do that in your own terminal"
    )
    for raw in SHELL_OPERATORS.split(command):
        text = REDIRECT_TARGET.sub(" ", raw)
        try:
            words = shlex.split(text, posix=True)
        except ValueError:
            words = text.split()
        while words and "=" in words[0] and not words[0].startswith("-"):
            words = words[1:]
        if not words:
            continue
        verb = os.path.basename(words[0]).lower()
        if verb == "find" and FIND_ACTIONS & set(words) and _find_reaches_agent_dir(words, folders):
            return message
        named = [w for w in words[1:] if _names_agent_dir(w, folders)]
        if not named:
            continue
        if verb == "git":
            sub = next((w for w in words[1:] if not w.startswith("-")), "")
            if sub not in GIT_READ:
                return message
            continue
        if verb not in DIR_READ_VERBS or (verb == "find" and FIND_ACTIONS & set(words)):
            return message
    return None


def blocked_path(path, rules):
    return is_protected(path) or is_secret(path, rules)


def reason_for(path, verb="names"):
    if is_protected(path):
        return (
            f"the call {verb} {os.path.basename(path.rstrip('/')) or path}, which denypeek "
            "protects so an agent cannot switch the guard off; change it in your own terminal"
        )
    return f"the call {verb} a secret file ({os.path.basename(path.rstrip('/'))})"


# --- resolving paths in tool input ---------------------------------------------------


def expand(token, cwd, for_glob=False):
    """The absolute path a token names. With `for_glob`, a Python glob pattern instead: the
    token's own glob syntax is converted by shell_glob, and the home and working folders are
    escaped, because the shell never treats those as patterns."""
    t = token.strip().strip("'\"")
    if not t:
        return None
    home = home_dir()
    if for_glob:
        t = shell_glob(t)
        home, cwd = glob.escape(home), glob.escape(cwd)
    for var in ("${HOME}", "$HOME"):
        t = t.replace(var, home)
    for var in ("${PWD}", "$PWD"):
        t = t.replace(var, cwd)
    t = HOME_VARS.sub(lambda _m: home.replace("\\", "/"), t)
    if t == "~" or t.startswith(("~/", "~\\")):
        t = home + t[1:]
    elif t.startswith("~"):
        t = os.path.expanduser(t)  # ~otheruser
    if not os.path.isabs(t) and not re.match(r"^[A-Za-z]:[\\/]", t):
        t = os.path.join(cwd, t)
    return os.path.normpath(t)


def path_hits(token, cwd, rules):
    """Paths named by one token, including braces and globs. Returns the blocked ones."""
    found = []
    for variant in expand_braces(token):
        found += _path_hits(variant, cwd, rules)
        if variant.startswith("@") and len(variant) > 1:  # curl -F f=@.env, --data @.env
            found += _path_hits(variant[1:], cwd, rules)
    return found


BRACE_SEQ = re.compile(r"\{(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.(-?\d+))?\}")


def _brace_sequence(m, limit):
    """Items of a bash/zsh sequence such as {m..o}, {1..9..2}, {z..a}; None if not one."""
    a, b, step = m.group(1), m.group(2), abs(int(m.group(3) or 1)) or 1
    if a.lstrip("-").isdigit() and b.lstrip("-").isdigit():
        lo, hi, fmt = int(a), int(b), str
    elif len(a) == 1 and len(b) == 1 and a.isalpha() and b.isalpha():
        lo, hi, fmt = ord(a), ord(b), chr
    else:
        return None
    rng = range(lo, hi + 1, step) if lo <= hi else range(lo, hi - 1, -step)
    return [fmt(v) for _, v in zip(range(limit), rng)]


def expand_braces(word, limit=256):
    """Bash brace expansion of {a,b} (nested allowed) and sequences such as {m..o}, capped at
    `limit` results."""
    seq = BRACE_SEQ.search(word)
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if seq and (not m or seq.start() < m.start()):
        items = _brace_sequence(seq, limit)
        if items is not None:
            out = []
            for item in items:
                tick()
                for w in expand_braces(word[: seq.start()] + item + word[seq.end() :], limit):
                    out.append(w)
                    if len(out) >= limit:
                        return out
            return out
    if not m:
        return [word]
    out = []
    for alt in m.group(1).split(","):
        tick()
        for w in expand_braces(word[: m.start()] + alt + word[m.end() :], limit):
            out.append(w)
            if len(out) >= limit:
                return out
    return out


def _path_hits(token, cwd, rules):
    full = expand(token, cwd)
    if not full:
        return []
    found = []
    if blocked_path(full, rules):
        found.append(full)
    if any(ch in token for ch in "*?["):
        candidates = []
        try:
            # recursive: zsh (and bash with globstar) read `**/` as any number of folders
            for n, match in enumerate(glob.iglob(expand(token, cwd, True), recursive=True)):
                tick()
                if n >= MAX_GLOB_RESULTS:
                    raise HookTimeout("a glob matches too many files to check")
                candidates.append(match)
        except (OSError, re.error):
            pass
        # glob skips hidden files for `*`; check names in the folder directly too.
        folder, pattern = os.path.split(full)
        try:
            literal_folder = not any(ch in os.path.dirname(token) for ch in "*?[")
            names = os.listdir(folder) if literal_folder else []
        except OSError:
            names = []
        candidates += [os.path.join(folder, n) for n in names if name_matches(n, pattern)]
        found += [c for c in candidates if blocked_path(c, rules)]
    return found


def folder_holds_secret(folder, rules, deadline, honours_ignores=True):
    """True if the folder (recursively) holds a secret file. Raises TimeoutError if too big.

    `honours_ignores`: the search tool skips gitignored folders such as node_modules (ripgrep,
    ag, git grep and the agents' search tools do; grep -r does not), so the walk may skip them.
    """
    skip = {".git", "__pycache__"} | ({"node_modules"} if honours_ignores else set())
    seen = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames + dirnames:
            seen += 1
            if seen > WALK_LIMIT or time.monotonic() > deadline:
                raise TimeoutError
            if blocked_path(os.path.join(dirpath, name), rules):
                return True
    return False


WINDOWS = sys.platform == "win32"
# Windows-shaped paths: a drive (C:\\), a UNC share (\\\\server\\), or a home variable followed by a
# backslash. Their backslashes are separators, not shell escapes.
WIN_PATH = re.compile(
    r"(?:\b[A-Za-z]:\\|\\\\[\w.$-]+\\|%[A-Za-z_]+%\\|\$\{?env:[A-Za-z_]+\}?\\)[^\s\"'|;&<>`()]*",
    re.I,
)
HOME_VARS = re.compile(
    r"%HOMEDRIVE%%HOMEPATH%|%USERPROFILE%|%HOME%|\$\{env:(?:USERPROFILE|HOME)\}|"
    r"\$env:(?:USERPROFILE|HOME)\b",
    re.I,
)


def windows_paths(text, windows=None):
    """Turn Windows path separators into '/' before shell-style splitting.

    On Windows (cmd and PowerShell) a backslash is never an escape, so all become '/'.
    Elsewhere only Windows-shaped paths are rewritten; other backslashes stay escapes.
    """
    if WINDOWS if windows is None else windows:
        return text.replace("\\", "/")
    return WIN_PATH.sub(lambda m: m.group(0).replace("\\", "/"), text)


ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")


def _ansi_c(match):
    """Decode bash $'...' quoting (\\x2e, \\056, \\n ...) into a plain quoted word."""
    body = match.group(1)
    try:
        decoded = body.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        decoded = body
    return shlex.quote(decoded)


# Glob syntax the shell expands only in some modes, rewritten as `*` (a superset). Run over a
# mask in which every quoted character is "a", so only unquoted syntax counts.
GLOB_FLAGS = re.compile(r"\(#[A-Za-z0-9.,:]*\)")  # zsh (#i) and similar
GLOB_GROUP = re.compile(r"(?<![$=<>\\])[@+!?*]?\([^()\s]*\)")  # zsh (a|b), bash/ksh @(...)
GLOB_EXTENDED = re.compile(r"\^[^/]*|##?")  # zsh EXTENDED_GLOB: ^x (rest of the name is
# "not x"), x# and x## (repeats)


def _unquote_with_mask(word):
    """(text without quotes, mask): the mask has "a" for every character that was quoted."""
    text, mask, i, quote = [], [], 0, None
    while i < len(word):
        c = word[i]
        if quote == "'":
            if c == "'":
                quote = None
            else:
                text.append(c)
                mask.append("a")
        elif c == "\\" and i + 1 < len(word) and quote != "'":
            text.append(word[i + 1])
            mask.append("a")
            i += 1
        elif quote == '"':
            if c == '"':
                quote = None
            else:
                text.append(c)
                mask.append("a" if c != "$" else "$")
        elif c in "'\"":
            quote = c
        else:
            text.append(c)
            mask.append(c)
        i += 1
    return "".join(text), "".join(mask)


def _rewrite(text, mask, rx, repl):
    while True:
        m = rx.search(mask)
        if not m:
            return text, mask
        text = text[: m.start()] + repl + text[m.end() :]
        mask = mask[: m.start()] + repl + mask[m.end() :]


def glob_variants(text):
    """Argument words rewritten so the guard's glob check covers shell modes it cannot see.

    zsh, the macOS default shell, expands `(a|b)` groups in arguments by default; with options
    an agent can turn on in the same command, bash and zsh also expand `@(...)`, `+(...)`,
    `!(...)` (extglob, kshglob) and zsh's `^x`, `x#`, `x~y` and `(#i)` (EXTENDED_GLOB). Each
    unquoted use becomes `*` (and `~y` is dropped), so the result matches at least what the
    shell could. The operator split below would otherwise cut `(a|b)` words apart. Words in
    command position (`(ls|wc)` is a subshell there) and comments are left alone."""
    out = []
    text = re.sub(r"(?:^|(?<=\s))#[^\n]*", "", text)  # comments
    for m in re.finditer(r"\S+", text):
        word = m.group(0)
        if not any(c in word for c in "()^#~"):
            continue
        before = text[: m.start()].rstrip()
        if not before or before[-1] in ";&|(\n":
            continue  # command position
        plain, mask = _unquote_with_mask(word)
        new, nmask = _rewrite(plain, mask, GLOB_FLAGS, "")
        for _ in range(8):  # nested groups, innermost first
            before_pass = new
            new, nmask = _rewrite(new, nmask, GLOB_GROUP, "*")
            if new == before_pass:
                break
        new, nmask = _rewrite(new, nmask, GLOB_EXTENDED, "*")
        cut = nmask.find("~", 1)
        if cut > 0:
            new, nmask = new[:cut], nmask[:cut]
        if new != plain and "(" not in nmask and ")" not in nmask:
            out.append(new)
    return out


def split_tokens(command, _resolve=True):
    """Shell-ish tokens. Splits on operators, quotes and $IFS tricks. Never runs anything."""
    text = unicodedata.normalize("NFC", command)
    # A backslash before a line break joins the lines: `cat .e\\<newline>nv` is `cat .env` (G7)
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    text = ANSI_C.sub(_ansi_c, text)
    text = windows_paths(text)
    text = text.replace('$"', '"')  # $"..." locale quoting is plain quoting here
    text = text.replace("${IFS}", " ").replace("$IFS", " ")
    groups = glob_variants(text)
    text = re.sub(r"[<>]+&?\d*", " ", text)  # redirections: cat<.env, >out
    tokens = []
    parts = SHELL_OPERATORS.split(text)
    for part in parts + [None]:
        if part is None:
            words = groups  # already unquoted
        else:
            try:
                words = shlex.split(part, posix=True)
            except ValueError:
                words = part.split()
        for w in words:
            tokens.append(w)
            if "=" in w and not w.startswith("="):  # --file=.env, VAR=.env, f=@.env
                tokens.append(w.split("=", 1)[1])
            if ":" in w:  # git show HEAD:.env, .env::$DATA, host:path
                tokens += [x for x in w.split(":") if x]
    if _resolve:
        resolved = substitute_variables(command)
        if resolved != command:
            more, more_parts = split_tokens(resolved, _resolve=False)
            return tokens + more, [t for t in SHELL_OPERATORS.split(text)] + more_parts
    return tokens, [t for t in SHELL_OPERATORS.split(text)]


ASSIGNMENT = re.compile(
    r"(?:^|[\s;&|(])(?:export[ \t]+|local[ \t]+|readonly[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)="
    r"('[^']*'|\"[^\"]*\"|[^\s;&|)]*)"
)


def substitute_variables(command):
    """`a=.e; cat ${a}nv` -> `a=.e; cat .env`: variables assigned in the same command, simple
    cases only (no arithmetic, arrays or command substitution in the value)."""
    values = {}
    for name, value in ASSIGNMENT.findall(command):
        if len(values) >= 200:
            break
        if value[:1] in ("'", '"') and value[-1:] == value[:1]:
            value = value[1:-1]
        values[name] = value
    if not values:
        return command
    text = command
    too_long = HookTimeout("the command's variables expand to too much text to check")
    for _ in range(3):
        before = text
        for name, value in values.items():
            tick()
            if len(value) > MAX_COMMAND:
                raise too_long
            pattern = re.compile(r"\$\{" + name + r"\}|\$" + name + r"(?![A-Za-z0-9_])")
            hits = len(pattern.findall(text))
            # R4: check the size before building the string, so nothing big is ever made
            if hits and len(text) + hits * len(value) > MAX_COMMAND:
                raise too_long
            if hits:
                text = pattern.sub(lambda _m, v=value: v, text)
        if text == before:
            break
    return text


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
    # grep -d recurse / --directories=recurse read the whole tree too (G6)
    dir_recurse = any(a in ("--directories=recurse", "-drecurse") for a in args) or any(
        a == "-d" and i + 1 < len(args) and args[i + 1] == "recurse" for i, a in enumerate(args)
    )
    recursive = (
        dir_recurse
        or prog in ("rg", "ag", "ack", "git-grep")
        or any(
            a in ("-r", "-R", "--recursive", "--dereference-recursive")
            or (a.startswith("-") and not a.startswith("--") and ("r" in a[1:] or "R" in a[1:]))
            for a in args
        )
    )
    if not recursive:
        return []
    cleaned, skip_next = [], False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-d", "-e", "-f", "--regexp", "--file", "--include", "--exclude", "-g", "-t"):
            skip_next = True  # the next word is this option's value
            continue
        cleaned.append(a)
    positional = [a for a in cleaned if not a.startswith("-")]
    paths = positional[1:] if prog not in ("git-grep",) else positional[1:]
    if not paths:
        paths = ["."]
    honours_ignores = prog in ("rg", "ag", "git-grep")
    out = []
    for p in paths:
        full = expand(p, cwd)
        if full and os.path.isdir(full):
            out.append((full, honours_ignores))
    return out


def cd_targets(parts, cwd):
    """Folders named by `cd` or `pushd` anywhere in the command (no argument means home)."""
    out = []
    for part in parts:
        try:
            words = shlex.split(part, posix=True)
        except ValueError:
            words = part.split()
        if words and words[0] in ("cd", "pushd", "chdir"):
            args = [w for w in words[1:] if not w.startswith("-")]
            target = expand(args[0], cwd) if args else home_dir()
            if target:
                out.append(target)
    return out


def switches_guard(tokens):
    """True for `denypeek guard install|uninstall` in any form (denypeek, python -m denypeek...)."""
    low = [os.path.basename(t).lower() for t in tokens]
    return (
        any("denypeek" in t for t in low)
        and "guard" in low
        and ("uninstall" in low or "install" in low)
    )


def check_command(command, cwd, rules, deadline, depth=0, extra=()):
    tokens, parts = split_tokens(command)
    if switches_guard(tokens):
        return (
            "denypeek guard install and uninstall change the guard itself; "
            "run them yourself in a terminal"
        )
    # `cd dir && cat .env`: relative paths are checked against every folder the command
    # changes into, as well as the starting one.
    folders = [cwd] + list(extra) + cd_targets(parts, cwd)
    if len(tokens) > MAX_TOKENS:
        raise HookTimeout("the command has too many words to check")
    for tok in tokens:
        tick()
        if depth < 3 and any(ch in tok for ch in " \t;|&<>$`"):
            # a nested script: bash -c '...', sh -lc "...", eval "..."
            reason = check_command(tok, cwd, rules, deadline, depth + 1, extra)
            if reason:
                return reason
            continue
        for folder in folders:
            hits = path_hits(tok, folder, rules)
            if hits:
                return reason_for(hits[0], "names")
    for part in parts:
        for folder, honours_ignores in grep_targets(part, cwd):
            try:
                if folder_holds_secret(folder, rules, deadline, honours_ignores):
                    return f"recursive search over {folder}, which holds a secret file"
            except TimeoutError:
                return f"recursive search over {folder}: too many files to check; narrow the path"
    return None


def patch_paths(text):
    out = []
    for line in text.splitlines():
        for prefix in ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "):
            if line.startswith(prefix):
                out.append(line[len(prefix) :].strip())
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
    """Return a reason string to deny, or None to allow. Raises HookTimeout when out of time."""
    _deadline[0] = time.monotonic() + HOOK_SECONDS
    deadline = time.monotonic() + WALK_SECONDS
    ti0 = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    cwd = event.get("cwd") or ti0.get("working_directory") or ti0.get("dir_path") or os.getcwd()
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
    # Folders the tool runs in, besides the session's cwd (G4): relative names are checked
    # against each of them.
    workdirs = []
    if isinstance(tool_input, dict):
        for k in WORKDIR_KEYS:
            v = tool_input.get(k)
            if isinstance(v, str) and v.strip() and len(v) <= MAX_PATH:
                d = expand(v.strip(), cwd)
                if d and d not in workdirs and d != os.path.normpath(cwd):
                    workdirs.append(d)
    scope = (
        {"tool_input": tool_input}
        if tool_input is not None
        else {k: v for k, v in event.items() if k in ("file_path", "command", "attachments")}
    )
    for key, s in strings_in(scope):
        tick()
        if switches_hooks_off(s[:1_000_000]):
            return (
                "the call would switch agent hooks off (disableAllHooks or hooks = false), "
                "which would disable denypeek; change hook settings in your own terminal"
            )
        if key in SHELL_KEYS and len(s) > MAX_COMMAND:
            return f"the command is too long to check ({len(s)} characters)"
        if key in SHELL_KEYS:
            if tool == "apply_patch" or s.lstrip().startswith("*** Begin Patch"):
                for p in patch_paths(s):
                    hits = path_hits(p, cwd, rules)
                    if hits:
                        return reason_for(hits[0], "edits")
                problem = patch_settings_problem(s, cwd)
                if problem:
                    return problem
                continue
            reason = check_command(s, cwd, rules, deadline, extra=workdirs)
            if not reason:
                folders = [cwd] + workdirs + cd_targets(SHELL_OPERATORS.split(s), cwd)
                reason = shell_settings_problem(windows_paths(s), folders) or shell_folder_problem(
                    windows_paths(s), folders
                )
            if reason:
                return reason
            continue
        if is_path_key(key):
            s = s.strip()  # only surrounding whitespace; the rest is checked as given
            if len(s) > MAX_PATH:
                return f"a path is too long to check ({len(s)} characters)"
            if "\n" in s or "\r" in s:
                return "a path contains a line break, so it cannot be checked"
        elif not s or "\n" in s or len(s) > MAX_PATH:
            continue  # file contents and other free text, not a path
        if not s and tool in MANY_FILE_TOOLS:
            s = "."  # an empty include may mean "everything"
        if not s:
            continue
        for folder in [cwd] + workdirs:
            hits = path_hits(s, folder, rules)
            if hits:
                return reason_for(hits[0], "uses")
            if (
                is_path_key(key)
                and is_agent_dir(expand(s, folder))
                and any(w in tool.lower() for w in ("delete", "remove", "move", "rename"))
            ):
                return "deleting or moving an agent's settings folder would remove the hook"
            if is_path_key(key):
                problem = settings_edit_problem(expand(s, folder) or "", tool_input)
                if problem:
                    return problem
        if tool in MANY_FILE_TOOLS:
            # Gemini read_many_files reads whole folders and recursive globs (G8)
            base = s.split("**", 1)[0] if "**" in s else s
            folder = expand(base or ".", cwd)
            if folder and os.path.isdir(folder):
                try:
                    if folder_holds_secret(folder, rules, deadline):
                        return f"reading many files under {folder}, which holds a secret file"
                except TimeoutError:
                    return f"reading many files under {folder}: too many to check; narrow it"
        if tool in GREP_TOOLS and key in ("path", "dir_path"):
            folder = expand(s, cwd)
            if folder and os.path.isdir(folder):
                try:
                    if folder_holds_secret(folder, rules, deadline):
                        return f"search over {folder}, which holds a secret file; narrow the path"
                except TimeoutError:
                    return f"search over {folder}: too many files to check; narrow the path"
    if (
        tool in GREP_TOOLS
        and isinstance(tool_input, dict)
        and not (tool_input.get("path") or tool_input.get("dir_path"))
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
    msg = f"denypeek blocked this: {reason}. If this is wrong, edit ~/.denypeek/secretfiles."
    if agent == "cursor":
        return json.dumps({"permission": "deny", "user_message": msg, "agent_message": msg}), 0
    if agent == "gemini":
        return json.dumps({"decision": "deny", "reason": msg}), 0
    # claude and codex share this shape
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": event_name or "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }
        }
    ), 0


def allow_output(agent):
    """Allow without approving: defer to the agent's own permission prompts."""
    if agent == "cursor":
        return json.dumps({"permission": "allow"}), 0  # Cursor blocks on empty output
    # An empty JSON object: no decision, so the agent's own prompts still apply. Always
    # answering lets the wrapper treat a silent exit as a failure (G1).
    return "{}", 0


def fail_closed(agent, why):
    msg = f"denypeek guard error ({why}); blocked to be safe. To remove the guard: {UNINSTALL}"
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
    if "--home" in argv:
        i = argv.index("--home")
        if i + 1 < len(argv) and argv[i + 1]:
            _home[0] = argv[i + 1]
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
    try:
        reason = decide(event, rules)
    except HookTimeout as exc:
        return fail_closed(agent, str(exc))
    if reason:
        out, code = deny_output(agent, event.get("hook_event_name"), reason)
        return out, code, reason
    out, code = allow_output(agent)
    return out, code, ""


def start_watchdog(agent, use_signals=True):
    """A last resort if the decision itself gets stuck: deny before the agent's timeout.

    POSIX: an interval timer raises HookTimeout in Python code, and a CPU limit kills a run
    stuck inside C code (the wrapper turns that exit into a block). Windows: a timer thread
    writes a denial and exits 2.
    """
    limit = HOOK_SECONDS + 0.5
    try:
        import signal

        if use_signals and hasattr(signal, "setitimer"):

            def on_alarm(_signum, _frame):
                raise HookTimeout("took too long to check")

            signal.signal(signal.SIGALRM, on_alarm)
            signal.setitimer(signal.ITIMER_REAL, limit)
            try:
                import resource

                soft = int(limit) + 2
                resource.setrlimit(resource.RLIMIT_CPU, (soft, soft + 1))
            except (ImportError, ValueError, OSError):
                pass
            return
    except (ImportError, ValueError, OSError):
        pass
    import threading

    def emergency():
        name = agent if agent in AGENTS else "claude"
        out, _code, msg = fail_closed(name, "took too long to check")
        try:
            os.write(1, out.encode())
            os.write(2, (msg + "\n").encode())
        finally:
            os._exit(2)

    timer = threading.Timer(limit, emergency)
    timer.daemon = True
    timer.start()


def main():
    agent = "claude"
    try:
        if "--agent" in sys.argv:
            agent = sys.argv[sys.argv.index("--agent") + 1]
    except IndexError:
        pass
    start_watchdog(agent)
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
