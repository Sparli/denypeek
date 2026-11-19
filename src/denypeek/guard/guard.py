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
# SPEC 3b T7: a recursive search walks the folder by names only. Set from a measurement (see
# specs/04-tree-walk.md, tools/measure_walk.py). Past either limit the search is denied
# (T8).
WALK_LIMIT = 100_000  # entries visited when a search covers a folder
WALK_SECONDS = 1.0
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


def is_network(path):
    """A Windows network path (\\\\host\\share, //host/share). Touching one makes Windows try
    to reach the host, which can take many seconds, so the guard never resolves or lists
    these: it judges them by name only. A URL split at `:` (https://x/y) also looks like one."""
    return WINDOWS and _norm(str(path)).startswith("//")


def resolved(path):
    """os.path.realpath, except for network paths (see is_network)."""
    if is_network(path):
        return path
    return os.path.realpath(path)


def is_secret(path, rules):
    """True if this path is a secret file (last matching pattern wins, like gitignore)."""
    candidates = {_norm(path)}
    try:
        candidates.add(_norm(resolved(path)))
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
        candidates.add(_norm(resolved(path)))
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


def shell_settings_problem(command, folders, depth=0):
    """Shell commands may read agent settings files but not write them, and may not use an
    agent settings folder itself as the source or target of a change (R2): `cp x .claude/`,
    `mv dir .claude`, `tar -C .claude`, `dd of=.claude/settings.json`."""
    for raw in SHELL_OPERATORS.split(command):
        for target in REDIRECT_TARGET.findall(raw):
            if any(settings_kind(expand(target, f) or "") for f in folders):
                return "the command writes an agent settings file; edit it in your own terminal"
    sw = shell_words(command, folders[0] if folders else ".")
    for script, _ in shell_scripts(sw, depth):
        problem = shell_settings_problem(script, folders, depth + 1)
        if problem:
            return problem
    for seg in sw.segments:
        words = [w for w in seg if not _skip_word(w)]
        while words and _is_assignment(words[0]) != -1:
            words = words[1:]
        if not words:
            continue
        literals = [w.literal for w in words]
        args = []
        for w in literals[1:]:
            args.append(w)
            if "=" in w:  # dd of=..., --target-directory=...
                args.append(w.split("=", 1)[1])
        files = [w for w in args if any(settings_kind(expand(w, f) or "") for f in folders)]
        dirs = [w for w in words[1:] if _names_agent_dir(w, folders)]
        dirs += [w for w in args if any(is_agent_folder(expand(w, f)) for f in folders)]
        if not files and not dirs:
            continue
        verb = os.path.basename(literals[0]).lower()
        if verb == "git":
            sub = next((w for w in literals[1:] if not w.startswith("-")), "")
            read_only = sub in GIT_READ
        else:
            folder_only = bool(dirs) and not files
            read_only = verb in READ_VERBS or (
                folder_only
                and (verb == "mkdir" or verb in DIR_READ_VERBS)
                and not (verb == "find" and FIND_ACTIONS & set(literals))
            )
        in_place = any(w.startswith("-i") or w == "--in-place" for w in literals)
        if verb in IN_PLACE_EDITORS and in_place:
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
    """True if the word, as written or widened (SPEC 3a G5), names an agent settings folder."""
    return any(is_agent_dir(p) for p in word_paths(word, folders))


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


# --- G7: deleting, moving or locking the home folder or a folder above it ---------------
G7_ANY_OPERAND = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "srm",
    "trash",
    "chmod",
    "chown",
    "chgrp",
    "chflags",
}
ANCESTOR_MESSAGE = (
    "the command may delete, move or lock your home folder or a folder above it, which holds "
    "denypeek and every agent's settings; do that in your own terminal"
)


def ancestor_dirs():
    """The home folder and every folder above it, also for CLAUDE_CONFIG_DIR and CODEX_HOME,
    as resolved, normalised paths (SPEC 3a G7)."""
    roots = [home_dir()]
    roots += [os.environ[v] for v in ("CLAUDE_CONFIG_DIR", "CODEX_HOME") if os.environ.get(v)]
    out = set()
    for r in roots:
        try:
            p = os.path.realpath(r)
        except (OSError, ValueError):
            continue
        while True:
            out.add(_norm(p).rstrip("/") or "/")
            parent = os.path.dirname(p)
            if parent == p:
                break
            p = parent
    return out


def is_ancestor(path):
    if not path:
        return False
    try:
        real = resolved(path)
    except (OSError, ValueError):
        real = path
    return (_norm(real).rstrip("/") or "/") in ancestor_dirs()


def _ancestor_problem(words, folders):
    """G7: one of the verb words below, and an operand naming an ancestor in any G5 reading.
    The verb may be any word of the simple command (sudo rm, env rm, /bin/rm, \\rm)."""
    lits = [w.literal for w in words]
    names = [os.path.basename(x).lower() for x in lits]

    def operands(after):
        return [w for w in words[after + 1 :] if not w.literal.startswith("-")]

    def names_ancestor(ws):
        return any(is_ancestor(p) for w in ws for p in word_paths(w, folders))

    for j, name in enumerate(names):
        if name in G7_ANY_OPERAND:
            ops = operands(j)
        elif name == "mv":
            ops = operands(j)
            if not any(x == "-t" or x.startswith("--target-directory") for x in lits[j:]):
                ops = ops[:-1]  # the last operand is where things go, unless -t names it
        elif name == "rsync" and any(
            x.startswith("--del") or x == "--remove-source-files" for x in lits[j:]
        ):
            ops = operands(j)
        elif name == "git" and "clean" in lits[j + 1 :]:
            ops = operands(lits.index("clean", j + 1))
            dirs = list(folders)
            for n in range(j + 1, len(lits) - 1):
                if lits[n] == "-C":
                    dirs += [expand(lits[n + 1], f) for f in folders]
            if any(is_ancestor(d) for d in dirs):
                return True
        else:
            continue
        if names_ancestor(ops):
            return True
    return False


def shell_folder_problem(command, folders, depth=0, env=None):
    message = (
        "the command may move, delete or change an agent's settings folder, which "
        "would remove the denypeek hook; do that in your own terminal"
    )
    sw = shell_words(command, folders[0] if folders else ".", env)
    for script, script_env in shell_scripts(sw, depth):
        problem = shell_folder_problem(script, folders, depth + 1, script_env)
        if problem:
            return problem
    for seg in sw.segments:
        words = [w for w in seg if not _skip_word(w)]
        while words and _is_assignment(words[0]) != -1:
            words = words[1:]
        if not words:
            continue
        if _ancestor_problem(words, folders):
            return ANCESTOR_MESSAGE
        literals = [w.literal for w in words]
        verb = os.path.basename(literals[0]).lower()
        if (
            verb == "find"
            and FIND_ACTIONS & set(literals)
            and _find_reaches_agent_dir(literals, folders)
        ):
            return message
        named = [w for w in words[1:] if _names_agent_dir(w, folders)]
        if not named:
            continue
        if verb == "git":
            sub = next((w for w in literals[1:] if not w.startswith("-")), "")
            if sub not in GIT_READ:
                return message
            continue
        if verb not in DIR_READ_VERBS or (verb == "find" and FIND_ACTIONS & set(literals)):
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


def expand(token, cwd):
    t = token.strip().strip("'\"")
    if not t:
        return None
    home = home_dir()
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
    """Blocked paths a tool's path field names. Tools do not run a shell, so only `*`, `?`,
    brackets and braces count as patterns, as some tools (read_many_files) expand those."""
    w = Word()
    w.chars = [(c, U if c in "*?[]{},." else Q) for c in token]
    return [p for p in word_paths(w, [cwd]) if blocked_path(p, rules)]


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


# --- the tree rule: SPEC 3b, recursive search ---------------------------------------------
# A recursive search is allowed only if nothing under the folders it reads matches the secret
# patterns. The walk skips nothing: no hidden names, no ignore files, no node_modules, for any
# tool, because what a tool skips depends on files and settings an agent can change. Only
# grep's own --include, --exclude and --exclude-dir narrow it, when written as literals. The
# walk looks at names only, and a name gets the full check only when it can match a pattern.

TIMEOUT_ADVICE = "try a shorter command, or search a narrower folder"
TREE_TOO_BIG = (
    "too many files to check in time; search a narrower folder, or skip dependency folders "
    "(with grep add `--exclude-dir=node_modules --exclude-dir=.venv`)"
)
TREE_SECRET = "a search from here would read a secret file"
GIT_GREP_UNCHECKED = (
    "git grep with a revision, the index (--cached) or a pattern path reads files the guard "
    "cannot list; search the working tree and name folders instead (for example "
    "`git grep foo -- src`)"
)
XARGS_SEARCH = (
    "a recursive search that gets its folders from xargs cannot be checked; name the folders "
    "in the command instead (for example `grep -rn foo src`)"
)
# Commands that run another command, which the hook looks through to find a search.
WRAPPERS = {
    "env",
    "command",
    "builtin",
    "nice",
    "nohup",
    "timeout",
    "time",
    "stdbuf",
    "exec",
    "xargs",
    "sudo",
    "doas",
    "caffeinate",
    "ionice",
}
SEARCH_TOOLS = {"grep", "egrep", "fgrep", "zgrep", "ugrep", "ack", "ag", "git-grep", "rg"}
# Public files that match a secret pattern by name but hold nothing secret. Exact path ends
# only: `certifi/cacert.pem` is the public Mozilla list of certificate authorities, in almost
# every Python virtualenv. It does not count for the tree rule (it still counts when named).
PUBLIC_FILES = (("certifi", "cacert.pem"),)
SHOW_PATHS = 2  # secret files named in the deny message
SHOW_FOLDERS = 8  # clear folders listed in it
SHOW_CHARS = 60  # longest name shown

_UNSAFE_CHARS = (
    set(range(0x20))
    | {0x7F}
    | set(range(0x80, 0xA0))
    | {0x061C, 0x200E, 0x200F, 0x2028}
    | {0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF}
)


def shown_name(text):
    """A name from disk, safe to show: control, bidi and other unsafe characters escaped as
    \\xNN or \\uNNNN (as the CLI does), and cut to SHOW_CHARS characters."""
    out = []
    for ch in text:
        o = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif o in _UNSAFE_CHARS:
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}")
        elif ch == "\\" and os.sep == "/":
            out.append("\\\\")
        else:
            out.append(ch)
    text = "".join(out)
    return text if len(text) <= SHOW_CHARS else text[: SHOW_CHARS - 1] + "…"


class Search:
    """One folder a search reads and what grep's own options narrow (T5). `reason`: deny at
    once with this text (a search whose folders or files the hook cannot tell)."""

    def __init__(self, folder, includes=(), excludes=(), exclude_dirs=(), reason=None):
        self.folder = folder
        self.includes, self.excludes, self.exclude_dirs = includes, excludes, exclude_dirs
        self.reason = reason


class _WalkLimit(Exception):
    pass


def tree_secret_reason(found, clear, more):
    """Message (a): why, the first secret files (relative to the folder), and the folders
    directly under it that the same walk found clear."""
    names = ", ".join(shown_name(f) for f in found[:SHOW_PATHS])
    msg = f"{TREE_SECRET} ({names}); search a narrower folder"
    if clear:
        listed = ", ".join(shown_name(c) for c in clear[:SHOW_FOLDERS])
        extra = len(clear) - SHOW_FOLDERS + more
        msg += f". Clear to search: {listed}" + (f" and {extra} more" if extra > 0 else "")
    else:
        msg += " (no folder directly under this one is clear), or leave the files out with "
        msg += "grep's `--exclude` or `--exclude-dir`"
    return msg


def tree_protected_reason(path):
    name = shown_name(os.path.basename(path.rstrip("/")) or path)
    return (
        f"the search covers {name}, which denypeek protects so an agent cannot switch the guard "
        "off; search a folder that does not hold it"
    )


def _protected_targets():
    dirs, files = protected_paths()
    home = _norm(os.path.normpath(home_dir())).rstrip("/")
    out = set(dirs) | set(files) | agent_dirs() | {home + "/.local/lib"}
    return {t.rstrip("/") for t in out}


def protected_under(folder):
    """T6: a protected path that is the folder, lies under it, or holds it; else None."""
    cands = {_norm(os.path.normpath(folder)).rstrip("/")}
    try:
        cands.add(_norm(os.path.realpath(folder)).rstrip("/"))
    except (OSError, ValueError):
        pass
    for t in sorted(_protected_targets()):
        for c in cands:
            if t == c or t.startswith(c + "/") or c.startswith(t + "/") or c == "":
                return t
    return None


def _last_part_regex(rules):
    """T7: one regex for the last path part any pattern's match needs, or None when a pattern
    has no such part (then every name gets the full check)."""
    out = []
    for _neg, pat, _m in rules:
        p = _norm(pat).rstrip("/")
        parts = [x for x in p.split("/") if x not in ("", "~")]
        while parts and parts[-1] == "**":
            parts.pop()
        if not parts or "**" in parts[-1]:
            return None
        out.append(_glob_to_re(parts[-1]))
    if not out:
        return re.compile("(?!)")
    return re.compile("^(?:" + "|".join(out) + ")$")


def fnmatch_case(name, pat):
    import fnmatch

    return fnmatch.fnmatchcase(name, pat)


def _public(path):
    parts = path.replace("\\", "/").split("/")
    return any(tuple(parts[-len(end) :]) == end for end in PUBLIC_FILES)


def search_tree(search, rules, deadline):
    """The reason to deny this search, or None: T6 first, then the walk (T5, T7, T8)."""
    if search.reason:
        return search.reason
    folder = search.folder
    t = protected_under(folder)
    if t:
        return tree_protected_reason(t)
    if is_protected(folder):
        return tree_protected_reason(folder)
    try:
        result = _walk(folder, search, rules, deadline)
    except _WalkLimit:
        return TREE_TOO_BIG
    return tree_secret_reason(*result) if result else None


def _walk(folder, search, rules, deadline):
    """None if no file the search can read under `folder` is blocked. Otherwise (the first
    secret files, relative to `folder`; the folders directly under it the walk found clear;
    how many more there are). Raises _WalkLimit past the entry cap or the time limit."""
    last_part = _last_part_regex(rules)
    root_full = last_part is None
    if not root_full:
        roots = {_norm(os.path.normpath(folder))}
        try:
            roots.add(_norm(os.path.realpath(folder)))
        except (OSError, ValueError):
            pass
        root_full = any(last_part.match(c) for r in roots for c in r.split("/") if c)
    found = []  # secret files, relative to the folder
    dirty = set()  # folders directly under it that hold one
    walked = set()  # folders directly under it that were walked
    # (folder, path relative to the start, the top folder it lies in, full check below?)
    stack = [(folder, "", None, root_full)]
    try:
        _walk_stack(stack, search, rules, deadline, last_part, found, dirty, walked)
    except _WalkLimit:
        if not found:
            raise
        return found, [], 0  # a secret file is certain; which folders are clear is not
    if not found:
        return None
    clear = sorted(
        (w for w in walked if w not in dirty and w != ".git"), key=lambda n: (n.startswith("."), n)
    )
    return found, clear, 0


def _walk_stack(stack, search, rules, deadline, last_part, found, dirty, walked):
    includes, excludes, exclude_dirs = search.includes, search.excludes, search.exclude_dirs
    seen = 0
    while stack:
        d, rel, top, full = stack.pop()
        if top in dirty:
            continue  # already known to hold a secret file: no need to look further
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            seen += 1
            if seen > WALK_LIMIT or (seen & 255 == 0 and time.monotonic() > deadline):
                raise _WalkLimit
            name = e.name
            path = f"{rel}/{name}" if rel else name
            try:
                is_link = e.is_symlink()
                is_dir = not is_link and e.is_dir(follow_symlinks=False)
            except OSError:
                is_link, is_dir = True, False  # cannot tell: give it the full check
            if is_dir:
                if any(fnmatch_case(name, x) for x in exclude_dirs):
                    continue  # T5
                need = full or bool(last_part.match(_norm(name)))
                if top is None:
                    walked.add(name)
                stack.append((e.path, path, top if top is not None else name, need))
                continue
            if includes and not any(fnmatch_case(name, x) for x in includes):
                continue  # T5: not included
            if (
                excludes
                and any(fnmatch_case(name, x) for x in excludes)
                and not any(fnmatch_case(name, x) for x in includes)
            ):
                continue  # T5: excluded and not included
            need = is_link or full or bool(last_part.match(_norm(name)))
            if need and not _public(path) and blocked_path(e.path, rules):
                if len(found) < SHOW_PATHS:
                    found.append(path)
                if top is None:
                    dirty.add(None)
                else:
                    dirty.add(top)
                    break
        if time.monotonic() > deadline:
            raise _WalkLimit


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
    return shlex.quote(_ansi_c_text(match.group(1)))


# --- shell words: SPEC section 3a, the shell-word rule ------------------------------------
# One lexer reads a command into words whose characters are tagged unquoted ("u") or quoted
# ("q"). Only unquoted characters can be glob syntax (G1). A literal value put into an
# unquoted $name counts as unquoted; values are data, so they never open quotes, start
# comments or end commands. Each word is then checked twice (G5): as written, and widened
# into a pattern that matches at least every path bash, zsh or sh could reach with it.

U, Q = "u", "q"
X = "x"  # zero-width mark: text the guard cannot resolve ($(...), unknown $name, $#, ...)
NUMERIC_RANGE = re.compile(r"<\d*-\d*>")
CMD_KEYWORDS = {"!", "if", "then", "else", "elif", "do", "while", "until", "time", "{", "}"}
WORD_WALK_LIMIT = 20_000  # entries one word's pattern may visit; past this it is denied (G6)
MAX_NESTING = 3  # $(...) inside $(...) ...; deeper is denied


class Word:
    __slots__ = ("chars", "cmdpos")

    def __init__(self, cmdpos=False):
        self.chars = []
        self.cmdpos = cmdpos

    @property
    def literal(self):
        return "".join(c for c, _ in self.chars)


class ShellWords:
    __slots__ = ("segments", "nested", "pipes", "env")

    def __init__(self):
        self.segments = []  # list of list[Word], one per simple command
        self.nested = []  # command text inside $(...), `...`, <(...), >(...), =(...)
        self.pipes = []  # per segment: True if a `|` sends its output to the next one
        self.env = {}  # variables bound in the command: name -> list of possible values

    def words(self):
        return [w for seg in self.segments for w in seg]


def _matching(s, i, open_ch, close_ch):
    """Index of the close_ch balancing s[i] == open_ch, skipping quotes; -1 if none."""
    depth, j, quote = 0, i, None
    while j < len(s):
        c = s[j]
        if quote:
            if c == "\\" and quote == '"':
                j += 2
                continue
            if c == quote:
                quote = None
        elif c == "\\":
            j += 2
            continue
        elif c in "'\"":
            quote = c
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


ANSI_SIMPLE = {
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}
ANSI_NUMERIC = re.compile(
    r"([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})"
)


def _ansi_c_text(body):
    """bash $'...' decoding: \\n, \\x2e, \\056, \\u002e, \\cX; anything else stays as written."""
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in ANSI_SIMPLE:
            out.append(ANSI_SIMPLE[nxt])
            i += 2
            continue
        if nxt == "c" and i + 2 < len(body):
            out.append(chr(ord(body[i + 2]) & 0x1F))
            i += 3
            continue
        m = ANSI_NUMERIC.match(body, i + 1)
        if m:
            octal, hx, u4, u8 = m.groups()
            code = int(octal, 8) if octal else int(hx or u4 or u8, 16)
            out.append(chr(code) if code < 0x110000 else "?")
            i = m.end()
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_assignment(word):
    """`name=...` with an unquoted `=`; returns the index of the `=` or -1."""
    lit = word.literal
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?=", lit)
    if not m:
        return -1
    eq = m.end() - 1
    return eq if word.chars[eq][1] == U else -1


class _Lexer:
    def __init__(self, text, cwd, home, env, choice=None):
        self.s, self.cwd, self.home, self.env = text, cwd, home, env
        self.choice = choice or {}  # name -> which of several possible values to use
        self.multi = set()  # names used that have several possible values
        self.out = ShellWords()
        self.out.env = env
        self.seg, self.word = [], None
        self.cmdpos, self.array, self.array_name = True, 0, None
        self.budget = MAX_COMMAND

    # words and segments
    def _start(self):
        if self.word is None:
            self.word = Word(self.cmdpos and not self.array)
        return self.word

    def _add(self, ch, kind):
        self.budget -= 1
        if self.budget < 0:
            raise HookTimeout("the command's variables expand to too much text to check")
        self._start().chars.append((ch, kind))

    def _end_word(self):
        w, self.word = self.word, None
        if w is None or not w.chars:
            return
        self.seg.append(w)
        if self.array and self.array_name:  # x=(a '.e*' c): each element is a possible value
            self.env.setdefault(self.array_name, []).append(w.literal)
            return
        eq = _is_assignment(w)
        if eq != -1:
            self.env[w.literal[:eq].split("[")[0]] = [w.literal[eq + 1 :]]
            return  # an assignment keeps command position
        lit = w.literal
        if w.cmdpos and (
            lit in CMD_KEYWORDS or lit in ("export", "local", "readonly", "declare", "typeset")
        ):
            return
        if not self.array:
            self.cmdpos = False

    def _end_segment(self, pipe=False):
        self._end_word()
        if self.seg:
            lits = [w.literal for w in self.seg]
            if len(lits) >= 3 and lits[0] == "for" and lits[2] == "in":
                self.env[lits[1]] = lits[3:]  # for f in a '.e*': $f may be each of them
            elif lits[0] == "set" and len(lits) > 1:
                if "--" in lits:
                    args = lits[lits.index("--") + 1 :]
                else:
                    args = [x for x in lits[1:] if not x.startswith(("-", "+"))]
                for n, v in enumerate(args, 1):
                    self.env[str(n)] = [v]
                self.env["@"] = list(args)
            self.out.segments.append(self.seg)
            self.out.pipes.append(pipe)
        self.seg, self.cmdpos = [], True

    def _opaque(self):
        """Mark run-time text: it adds no characters, but a path part that starts with it
        does not start with a written wildcard (G8)."""
        self._add("", X)

    def _splice(self, value, quoted):
        """A variable's literal value: data. Unquoted, it may glob and is split on blanks."""
        for ch in value:
            if not quoted and ch in " \t\n":
                self._end_word()
            else:
                self._add(ch, Q if quoted else U)

    def _variable(self, name, quoted):
        if name == "IFS":
            value, quoted = (" ", False) if not quoted else (" ", True)
        elif name == "HOME":
            value = self.home
            quoted = True  # a path the shell inserts; its own characters are not globs
        elif name == "PWD":
            value, quoted = self.cwd, True
        else:
            values = self.env.get(name)
            value = None
            if values:
                if len(values) > 1:
                    self.multi.add(name)
                value = values[min(self.choice.get(name, 0), len(values) - 1)]
        if value is not None:
            self._start()
            self._splice(value, quoted)
        else:
            self._opaque()  # unknown: run-time text (known miss 2); the word still exists

    def _nested(self, i, open_ch, close_ch):
        end = _matching(self.s, i, open_ch, close_ch)
        if end == -1:
            self.out.nested.append(self.s[i + 1 :])
            return len(self.s)
        self.out.nested.append(self.s[i + 1 : end])
        self._opaque()
        return end + 1

    def _dollar(self, i, quoted):
        s = self.s
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if nxt == "'" and not quoted:
            end = i + 2
            while end < len(s) and s[end] != "'":
                end += 2 if s[end] == "\\" else 1
            for ch in _ansi_c_text(s[i + 2 : end]):
                self._add(ch, Q)
            return end + 1
        if nxt == '"' and not quoted:
            return i + 1  # $"..." is "..." here
        if s.startswith("$((", i):
            end = _matching(s, i + 1, "(", ")")
            self._opaque()
            return len(s) if end == -1 else end + 1  # arithmetic: run-time text
        if nxt == "(":
            return self._nested(i + 1, "(", ")")
        if nxt == "{":
            end = _matching(s, i + 1, "{", "}")
            if end == -1:
                self._add("$", Q if quoted else U)
                return i + 1
            body = s[i + 2 : end].lstrip("~=^")  # zsh ${~x}, ${=x}, ${^x}
            arr = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\[[^\]]*\]", body)
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*|\d+|[@*])(:?[-=+])?(.*)", body, re.S)
            if arr:
                self._variable(arr.group(1), quoted)  # ${a[0]}, ${a[@]}: any element
            elif m and not m.group(2) and not m.group(3):
                self._variable("@" if m.group(1) == "*" else m.group(1), quoted)
            elif m and m.group(2) and m.group(2).lstrip(":") in "-=":
                # ${x:-word}: when x is unset the shell uses `word`; check that reading too
                sub = _Lexer(m.group(3), self.cwd, self.home, self.env)
                sub.run()
                for w in sub.out.words():
                    self._splice(w.literal, quoted)
                self.out.nested.extend(sub.out.nested)
            else:
                self._opaque()  # ${#x}, ${x#p}, ${x^^}, ${x[1]}: run-time text
            return end + 1
        m = re.match(r"[~=^]*([A-Za-z_][A-Za-z0-9_]*)", s[i + 1 :])  # zsh $~x, $=x, $^x
        if m:
            self._variable(m.group(1), quoted)
            return i + 1 + m.end()
        if nxt and (nxt.isdigit() or nxt in "@*"):
            self._variable("@" if nxt in "@*" else nxt, quoted)  # $1, $@: bound by set --
            return i + 2
        if nxt and nxt in "#?$!-":
            self._opaque()  # $#, $?, $$ ...: run-time text
            return i + 2
        self._add("$", Q if quoted else U)
        return i + 1

    def run(self):
        s, i = self.s, 0
        while i < len(s):
            tick()
            c = s[i]
            if c in " \t":
                self._end_word()
                i += 1
            elif c == "|" and s.startswith("||", i):
                self._end_segment()
                i += 2
            elif c == "|":
                self._end_segment(pipe=True)  # `|` and `|&` send output to the next command
                i += 2 if s.startswith("|&", i) else 1
            elif c in "\n;&":
                self._end_segment()
                i += 1
            elif c == "#" and self.word is None:
                end = s.find("\n", i)
                i = len(s) if end == -1 else end  # a comment
            elif c == "'":
                end = s.find("'", i + 1)
                end = len(s) if end == -1 else end
                self._start()
                for ch in s[i + 1 : end]:
                    self._add(ch, Q)
                i = end + 1
            elif c == '"':
                i = self._double(i + 1)
            elif c == "\\":
                if i + 1 < len(s):
                    self._add(s[i + 1], Q)
                i += 2
            elif c == "$":
                i = self._dollar(i, False)
            elif c == "`":
                end = s.find("`", i + 1)
                end = len(s) if end == -1 else end
                self.out.nested.append(s[i + 1 : end])
                self._opaque()
                i = end + 1
            elif c == "<" and NUMERIC_RANGE.match(s, i):
                end = NUMERIC_RANGE.match(s, i).end()
                for ch in s[i:end]:
                    self._add(ch, U)  # zsh <1-99> and <->: a pattern, not a redirection
                i = end
            elif c in "<>":
                if i + 1 < len(s) and s[i + 1] == "(":
                    # process substitution: its contents are a command. At the start of a word
                    # that is all; in the middle, shells differ, so it also widens (G3).
                    mid = self.word is not None and bool(self.word.chars)
                    end = self._nested(i + 1, "(", ")")
                    if mid:
                        for ch in s[i:end]:
                            self._add(ch, U)
                    i = end
                    continue
                m = re.match(r"\d*\s*$", self.word.literal) if self.word else None
                if self.word is not None and m and all(k == U for _, k in self.word.chars):
                    self.word = None  # the fd number in 2>file
                self._end_word()
                j = i
                while j < len(s) and s[j] in "<>&|":
                    j += 1
                i = j  # the next word is the redirection target, checked like any word
            elif c == "(":
                i = self._paren(i)
            elif c == ")":
                if self.array:
                    self._end_word()
                    self.array -= 1
                    if not self.array:
                        self.array_name = None
                        self._end_word()
                else:
                    self._end_segment()
                i += 1
            elif c == "=" and self.word is None and i + 1 < len(s) and s[i + 1] == "(":
                i = self._nested(i + 1, "(", ")")  # zsh =(...)
            else:
                self._add(c, U)
                i += 1
        self._end_segment()
        return self.out

    def _double(self, i):
        s = self.s
        self._start()
        while i < len(s):
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\" and i + 1 < len(s) and s[i + 1] in '$`"\\\n':
                self._add(s[i + 1], Q)
                i += 2
            elif c == "$":
                i = self._dollar(i, True)
            elif c == "`":
                end = s.find("`", i + 1)
                end = len(s) if end == -1 else end
                self.out.nested.append(s[i + 1 : end])
                i = end + 1
            else:
                self._add(c, Q)
                i += 1
        return i

    def _paren(self, i):
        w = self.word
        if w is not None and w.chars and w.chars[-1] == ("=", U) and _is_assignment(w) != -1:
            self.array += 1  # x=(a b c): the elements are words; the `(` is not a glob
            self.array_name = w.literal[: _is_assignment(w)].split("[")[0]
            self._end_word_keep_array()
            return i + 1
        if w is None and self.cmdpos and not self.array:
            self._end_segment()  # a subshell: (cd src && ls)
            return i + 1
        # An unquoted `(` in an argument: a glob group in zsh, or after @ + ! ? * in
        # extglob. Keep it and everything up to its balancing `)` in the word. After a `=`
        # in the middle of a word it may also be zsh =(...), so its contents are a command too.
        end = _matching(self.s, i, "(", ")")
        if w is not None and w.chars and w.chars[-1] == ("=", U) and end != -1:
            self.out.nested.append(self.s[i + 1 : end])
        if end == -1 or "\n" in self.s[i:end]:
            self._add("(", U)
            return i + 1
        self._add("(", U)
        j = i + 1
        while j < end:
            c = self.s[j]
            if c == "'":
                e = self.s.find("'", j + 1)
                for ch in self.s[j + 1 : e]:
                    self._add(ch, Q)
                j = e + 1
            elif c == '"':
                j = self._double(j + 1)
            elif c == "\\" and j + 1 < end:
                self._add(self.s[j + 1], Q)
                j += 2
            elif c == "$":
                j = self._dollar(j, False)
            else:
                self._add(c, U)
                j += 1
        self._add(")", U)
        return end + 1

    def _end_word_keep_array(self):
        w, self.word = self.word, None
        if w is not None and w.chars:
            self.seg.append(w)
            eq = _is_assignment(w)
            if eq != -1:
                self.env.pop(w.literal[:eq].split("[")[0], None)


MAX_FORKS = 64  # readings of one command when variables have several possible values


def shell_words(command, cwd, env=None):
    """Lex a command (SPEC 3a G1). A variable that may hold several values (a `for` list,
    `set --`, an array) is read once per value, and the words of every reading are kept.
    On Windows a backslash is a path separator to cmd and PowerShell but an escape to bash
    (Git Bash, which agents use there), so both readings are kept."""
    text = unicodedata.normalize("NFC", command)
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    readings = [windows_paths(text)]
    if WINDOWS and "\\" in text:
        readings.append(WIN_PATH.sub(lambda m: m.group(0).replace("\\", "/"), text))
    out = None
    for reading in readings:
        more = _read_all(reading, cwd, env)
        if out is None:
            out = more
        else:
            out.segments += more.segments
            out.pipes += more.pipes
            out.nested += more.nested
    return out


def _read_all(text, cwd, env):
    home = home_dir()
    base = dict(env or {})
    first = _Lexer(text, cwd, home, dict(base))
    out = first.run()
    names = sorted(first.multi)
    if not names:
        return out
    sizes = [max(len(first.env.get(n) or [None]), 1) for n in names]
    total = 1
    for n in sizes:
        total *= n
    if total > MAX_FORKS:
        raise HookTimeout("variables in the command have too many possible values to check")
    for k in range(1, total):
        choice, rest = {}, k
        for name, n in zip(names, sizes):
            choice[name], rest = rest % n, rest // n
        more = _Lexer(text, cwd, home, dict(base), choice).run()
        out.segments += more.segments
        out.pipes += more.pipes
        out.nested += more.nested
    return out


# --- from a word to paths ------------------------------------------------------------------


def _brace_expand(chars, limit=256):
    """Bash and zsh brace expansion (G3d): {a,b} lists and {x..y} sequences, exactly; nested
    allowed; unquoted braces only. Anything else stays as written."""
    n = len(chars)
    for i in range(n):
        if chars[i] != ("{", U):
            continue
        depth, j, commas = 0, i, []
        while j < n:
            ch = chars[j]
            if ch == ("{", U):
                depth += 1
            elif ch == ("}", U):
                depth -= 1
                if depth == 0:
                    break
            elif ch == (",", U) and depth == 1:
                commas.append(j)
            j += 1
        if j >= n:
            continue
        inner = chars[i + 1 : j]
        if commas:
            bounds = [i] + commas + [j]
            alts = [chars[a + 1 : b] for a, b in zip(bounds, bounds[1:])]
        else:
            m = BRACE_SEQ.fullmatch("{" + "".join(c for c, _ in inner) + "}")
            items = _brace_sequence(m, limit) if m and all(k == U for _, k in inner) else None
            if items is None:
                continue  # literal, or `..` that is not a sequence: widened later (G3)
            alts = [[(c, U) for c in item] for item in items]
        out = []
        for alt in alts:
            tick()
            for w in _brace_expand(chars[:i] + alt + chars[j + 1 :], limit):
                out.append(w)
                if len(out) >= limit:
                    return out
        return out
    return [chars]


def _pieces(chars):
    """The word, the text after `=` (--file=.env, VAR=.env), the parts around `:`
    (HEAD:.env) and the text after a leading `@` (curl -F f=@.env)."""
    out = [chars]
    lit = "".join(c for c, _ in chars)
    if "=" in lit and not lit.startswith("="):
        out.append(chars[lit.index("=") + 1 :])
    if ":" in lit:
        start = 0
        for k, (c, _) in enumerate(chars + [(":", Q)]):
            if c == ":":
                if k > start:
                    out.append(chars[start:k])
                start = k + 1
    out += [p[1:] for p in list(out) if p and p[0][0] == "@" and len(p) > 1]
    return out


def _tilde(chars, folders, home):
    """(base folders, rest) for a word that starts with an unquoted `~` (G4), else None."""
    if not chars or chars[0] != ("~", U):
        return None
    k = 1
    while k < len(chars) and chars[k][0] != "/":
        k += 1
    head = "".join(c for c, _ in chars[1:k])
    rest = chars[k + 1 :] if k < len(chars) else []
    if head == "":
        return [home], rest
    if head == "+":
        return list(folders), rest
    return [home] + list(folders), rest  # ~-, ~user, zsh ~name: an unknown folder


GLOB_CHARS = set("*?[")
OPERATOR_CHARS = set("(#^{<~")


def _has_glob(chars):
    return any(k == U and (c in GLOB_CHARS or c in OPERATOR_CHARS) for c, k in chars)


_HIDDEN_CACHE = {}
# Set only while choosing a deny message (hidden_only_reason); never while deciding.
_WALK_AS_AUTO = [False]

# The deny message when only G8 `always` made a pattern reach a secret file (QA, readiness
# run at a507027). Fixed wording: no text from the command or from file names.
HIDDEN_GLOB_REASON = (
    "a `*`, `?` or `[...]` at the start of a name also matches hidden files here, and a hidden "
    "secret file is in reach (denypeek's hidden-files setting is `always`). "
    "Name the files instead, for example `ls` or `cat *.md`"
)


def hidden_only_reason(word, folders, rules):
    """HIDDEN_GLOB_REASON when the word reaches a blocked path only because hidden names count
    (walked as `auto` would, it reaches none), else None. Picks the message only: the call is
    already denied, and any error or time-out here keeps the usual message."""
    if hidden_names() != "always":
        return None
    _WALK_AS_AUTO[0] = True
    try:
        reached = word_paths(word, folders)
        if any(blocked_path(p, rules) for p in reached):
            return None
        return HIDDEN_GLOB_REASON
    except Exception:
        return None
    finally:
        _WALK_AS_AUTO[0] = False


def hidden_names():
    """SPEC 3a G8: "auto" or "always", from `hidden_names` in ~/.denypeek/guard-state.json.
    A missing, unreadable or unknown value means "always", and so does Windows, where
    PowerShell and cmd wildcards match dot files."""
    if WINDOWS:
        return "always"
    path = os.path.join(home_dir(), ".denypeek", "guard-state.json")
    try:
        key = (path, os.stat(path).st_mtime_ns)
    except (OSError, ValueError):
        return "always"
    if key not in _HIDDEN_CACHE:
        value = "always"
        try:
            with open(path, encoding="utf-8") as f:
                data = json.loads(f.read(1_000_000))
            if isinstance(data, dict) and data.get("hidden_names") == "auto":
                value = "auto"
        except (OSError, ValueError):
            pass
        _HIDDEN_CACHE.clear()
        _HIDDEN_CACHE[key] = value
    return _HIDDEN_CACHE[key]


def _bracket_close(chars, i):
    """Index of the `]` closing an unquoted bracket at i (POSIX rules), or -1."""
    j = i + 1
    if j < len(chars) and chars[j][0] in "!^":
        j += 1
    if j < len(chars) and chars[j][0] == "]":
        j += 1
    while j < len(chars):
        c, k = chars[j]
        if c == "/":
            return -1
        if c == "[" and k == U and j + 1 < len(chars) and chars[j + 1][0] in ":=.":
            mark = chars[j + 1][0]
            e = j + 2
            while e + 1 < len(chars) and not (chars[e][0] == mark and chars[e + 1][0] == "]"):
                e += 1
            if e + 1 < len(chars):
                j = e + 2
                continue
        if c == "]" and k == U:
            return j
        j += 1
    return -1


def _closes_after_slash(chars, i, open_ch, close_ch):
    """True if the bracket, group or brace opening at i could end after a `/` (G3c)."""
    rest = chars[i + 1 :]
    slash = next((n for n, (c, _) in enumerate(rest) if c == "/"), -1)
    if slash == -1:
        return False
    if open_ch == "[":
        return any(c == "]" and k == U for c, k in rest[slash:])
    depth = 1
    for n, (c, k) in enumerate(rest):
        if k != U:
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return n > slash
    return True  # never closes: it could reach anywhere


def _operator_at(chars, i):
    """Is the unquoted char at i a pattern operator in some covered mode (G3)?"""
    c = chars[i][0]
    nxt = chars[i + 1] if i + 1 < len(chars) else ("", Q)
    if c in "@+!?*<>" and nxt == ("(", U):  # extglob, and <(...) >(...) inside a word
        return True
    if c in "(#^":
        return True
    if c == "{":
        depth, j = 0, i
        while j < len(chars):
            if chars[j] == ("{", U):
                depth += 1
            elif chars[j] == ("}", U):
                depth -= 1
                if depth == 0:
                    return ".." in "".join(x for x, _ in chars[i + 1 : j])
            j += 1
        return False  # never closes: literal
    if c == "<":
        j = i + 1
        while j < len(chars) and chars[j][0] in "0123456789-" and chars[j][1] == U:
            j += 1
        return j < len(chars) and chars[j] == (">", U)
    return False


_CLOSER = {"[": "]", "(": ")", "{": "}", "<": ">"}


def _g3c_at(chars, i):
    """Is the unquoted character at i a bracket, group, brace or <...> that could close after a
    `/` (G3c)? For a bracket: any later `/` followed by a `]`, as shells disagree on its end."""
    c, k = chars[i]
    if k != U:
        return False
    if c == "[":
        return _closes_after_slash(chars, i, "[", "]")
    if c in "@+!?*<>" and i + 1 < len(chars) and chars[i + 1] == ("(", U):
        return _closes_after_slash(chars, i + 1, "(", ")")
    if c in "({<" and _operator_at(chars, i):
        return _closes_after_slash(chars, i, c, _CLOSER[c])
    return False


def widen(chars):
    """The widened pattern of a word (G2, G3): a list of path parts, each ("lit", text),
    ("pat", regex, dot) or ("any", regex-or-None, dot), and a flag: the last part also stands
    for everything under it, at any depth. `dot`: the part may also stand for `.` and `..`
    (G2: only a part that begins with a literal `.` or with a G3 operator). None if the word
    holds no glob syntax."""
    if not _has_glob(chars):
        return None
    # G3b: an unquoted `~` that is not at the start of the word cuts the whole word
    for n in range(1, len(chars)):
        if chars[n] == ("~", U) and chars[n - 1][0] not in "=:":
            chars = chars[:n]
            break
    # G3c: when a bracket, group or brace anywhere in the word could close after a `/`, the
    # cut is word-wide, at the earliest G3 or G3c operator; all after it is any text, any depth
    wordwide = any(_g3c_at(chars, n) for n in range(len(chars)))
    parts, cur, tree = [], [], False
    op_start = [False]
    i = 0

    def close_part():
        toks = list(cur)
        if not toks:
            parts.append(("lit", ""))
            return
        if all(t[0] == "lit" for t in toks):
            parts.append(("lit", "".join(t[1] for t in toks)))
            return
        rx = "".join(re.escape(t[1]) if t[0] == "lit" else t[1] for t in toks)
        dot = (toks[0][0] == "lit" and toks[0][1] == ".") or op_start[0]
        # G8: does the part start with a `*`, `?` or bracket written in the command?
        lead = toks[0][0] in ("star", "one")
        if any(
            t == ("star", ".*") and n + 1 < len(toks) and toks[n + 1] == ("star", ".*")
            for n, t in enumerate(toks)
        ):
            parts.append(("any", None if rx == ".*.*" else rx, dot, lead))
        else:
            parts.append(("pat", rx, dot, lead))

    def cut(at_hash, operator=True):
        if at_hash and cur:
            cur.pop()  # G3a: `#` repeats the unit before it, which may be absent
        if not cur and operator:
            op_start[0] = True  # G2: a part that begins with a G3 operator; not a bracket
        cur.append(("cut", ".*"))  # widened text: always counts hidden names (G8)

    while i < len(chars):
        c, k = chars[i]
        if c == "/":
            close_part()
            cur, op_start[0] = [], False
            i += 1
            continue
        if wordwide and _g3c_at(chars, i):
            cut(False, operator=c != "[")
            tree = True
            break
        is_op = k == U and c in OPERATOR_CHARS | set("@+!?*>") and _operator_at(chars, i)
        if is_op and wordwide:
            cut(c == "#")
            tree = True
            break
        if is_op:
            cut(c == "#")
            while i < len(chars) and chars[i][0] != "/":
                i += 1  # G3: the rest of this path part is any text
            continue
        if k == U and c == "[":
            end = _bracket_close(chars, i)
            cur.append(("one", "."))
            i = end + 1 if end != -1 else i + 1
            continue
        if k == U and c == "*":
            cur.append(("star", ".*"))
        elif k == U and c == "?":
            cur.append(("one", "."))
        else:
            cur.append(("lit", c))
        i += 1
    close_part()
    return parts, tree


class _Budget:
    def __init__(self):
        self.left = WORD_WALK_LIMIT

    def spend(self, n=1):
        self.left -= n
        tick()
        if self.left < 0:
            raise HookTimeout("a pattern in the command matches too many files to check")


def _entries(folder, budget):
    if is_network(folder):
        return []  # never list a network share (see is_network)
    try:
        with os.scandir(folder) as it:
            names = []
            for e in it:
                budget.spend()
                names.append(e.name)
            return names
    except OSError:
        return []


def _descendants(path, budget, include_self=True, skip_hidden=False):
    out = [path] if include_self else []
    stack = [path]
    while stack:
        d = stack.pop()
        if is_network(d) or not os.path.isdir(d) or os.path.islink(d) and d != path:
            continue
        for n in _entries(d, budget):
            if skip_hidden and n.startswith("."):
                continue
            p = os.path.join(d, n)
            out.append(p)
            if os.path.isdir(p) and not os.path.islink(p):
                stack.append(p)
    return out


def walk_pattern(bases, parts, tree, budget):
    """Every existing path the widened pattern can reach from the base folders."""
    cur = list(dict.fromkeys(bases))
    globbed = False
    auto = _WALK_AS_AUTO[0] or hidden_names() == "auto"
    for n, part in enumerate(parts):
        kind = part[0]
        nxt = []
        if kind == "lit":
            nxt = [os.path.join(d, part[1]) if part[1] else d for d in cur]
            if globbed:  # a shell expands a pattern only to paths that exist
                nxt = [x for x in nxt if not is_network(x) and os.path.lexists(x)]
                if not part[1]:  # `*/`: a trailing slash matches folders only
                    nxt = [x for x in nxt if os.path.isdir(x)]
        else:
            globbed = True
            rx = part[1]
            first_dot = part[2]
            # G8 auto: a `*`, `?` or bracket written at the start of a part skips hidden names
            hide = auto and part[3]
            if kind == "any":
                dirs = []
                for d in cur:
                    dirs += [
                        p for p in _descendants(d, budget, skip_hidden=hide) if os.path.isdir(p)
                    ]
                if rx is None:  # a part that is exactly `**`
                    if n == len(parts) - 1:
                        for d in cur:
                            nxt += _descendants(d, budget, skip_hidden=hide)
                    else:
                        nxt = dirs
                    cur = list(dict.fromkeys(nxt))
                    continue
                cur = dirs
            pat = re.compile(rx.replace(".*.*", ".*"), re.S | re.I)
            for d in cur:
                names = _entries(d, budget)
                if hide:
                    names = [x for x in names if not x.startswith(".")]
                if first_dot:
                    names += [".", ".."]
                nxt += [os.path.join(d, x) for x in names if pat.fullmatch(x)]
        cur = list(dict.fromkeys(nxt))
        if not cur:
            return []
    if tree:
        out = []
        for p in cur:
            out += _descendants(p, budget)
        cur = out
    return [os.path.normpath(p) for p in cur]


def _word_paths(chars, folders, budget):
    """Paths a word names (G5): as written, and through its widened pattern."""
    home = home_dir()
    out = []
    for expanded in _brace_expand(chars):
        for n, piece in enumerate(_pieces(expanded)):
            if not piece:
                continue
            literal = "".join(c for c, _ in piece)
            t = _tilde(piece, folders, home)
            if t is not None:
                bases, rest = t
                rest_lit = "".join(c for c, _ in rest)
                out += [os.path.normpath(os.path.join(b, rest_lit)) for b in bases]
            else:
                rest = piece
                for f in folders:
                    full = expand(literal, f)
                    if full:
                        out.append(full)
                if literal.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", literal):
                    bases = [os.path.abspath(os.sep)]
                    rest = piece[1:] if literal[:1] in "/\\" else piece
                else:
                    bases = list(folders)
            if len(literal) > MAX_PATH:
                raise HookTimeout("a path in the command is too long to check")
            # The shell globs the whole word only; the text after `=`, `:` or `@` is a name a
            # program may read, so it is checked as written (above), not as a pattern.
            w = widen(rest) if n == 0 else None
            if w is not None:
                parts, tree = w
                out += walk_pattern(bases, parts, tree, budget)
    return out


def word_paths(word, folders):
    """All paths a lexed word can name, from every working folder."""
    return _word_paths(list(word.chars), list(folders), _Budget())


def plain_word(text):
    """A word from a tool's path field: every character counts as written."""
    w = Word()
    w.chars = [(c, U) for c in text]
    return w


def split_tokens(command, _resolve=True):
    """Shell-ish tokens. Splits on operators, quotes and $IFS tricks. Never runs anything."""
    text = unicodedata.normalize("NFC", command)
    # A backslash before a line break joins the lines: `cat .e\\<newline>nv` is `cat .env` (G7)
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    text = ANSI_C.sub(_ansi_c, text)
    text = windows_paths(text)
    text = text.replace('$"', '"')  # $"..." locale quoting is plain quoting here
    text = text.replace("${IFS}", " ").replace("$IFS", " ")
    text = re.sub(r"[<>]+&?\d*", " ", text)  # redirections: cat<.env, >out
    tokens = []
    for part in SHELL_OPERATORS.split(text):
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


# Options that take a value in the next word (or after `=`). A value is never a path, so a
# wrong entry here could hide a folder; only options known to take a value are listed.
# "optional": the next word may or may not be the value (it differs between BSD and GNU grep,
# or is unverified); the hook walks the paths of both readings. Checked against BSD grep 2.6.0
# by running it; GNU grep from its manual: both take the next word for every "long" option
# below that each has (BSD lacks --exclude-from and --group-separator).
GREP_VALUE_OPTS = {
    "short": set("efmABCdD"),
    "long": {
        "--regexp",
        "--file",
        "--max-count",
        "--after-context",
        "--before-context",
        "--directories",
        "--devices",
        "--include",
        "--exclude",
        "--exclude-dir",
        "--exclude-from",
        "--label",
        "--binary-files",
        "--group-separator",
    },
    # BSD grep takes `--context`'s value only after `=`; GNU grep takes the next word
    "optional": {"--context"},
}
RG_VALUE_OPTS = {
    "short": set("efgtTmABCMjEdr"),
    "long": {
        "--regexp",
        "--file",
        "--glob",
        "--iglob",
        "--type",
        "--type-not",
        "--type-add",
        "--type-clear",
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
        "--max-columns",
        "--threads",
        "--encoding",
        "--max-depth",
        "--replace",
        "--pre",
        "--pre-glob",
        "--ignore-file",
        "--max-filesize",
        "--path-separator",
        "--sort",
        "--sortr",
        "--color",
        "--colors",
        "--context-separator",
        "--field-context-separator",
        "--field-match-separator",
        "--engine",
        "--dfa-size-limit",
        "--regex-size-limit",
        "--hostname-bin",
        "--hyperlink-format",
        "--generate",
    },
}
AG_VALUE_OPTS = {
    "short": set("Ggmp"),
    "long": {
        "--file-search-regex",
        "--ignore",
        "--ignore-dir",
        "--depth",
        "--pager",
        "--path-to-ignore",
        "--max-count",
    },
    # ag's context options take an optional count [unverified: ag is not installed here]
    "optional": {"-A", "-B", "-C", "--after", "--before", "--context"},
}
# git takes an optional value only when attached (`-Ox`, `--open-files-in-pager=x`), so `-O`
# and `--open-files-in-pager` never take the next word.
GIT_GREP_VALUE_OPTS = {
    "short": set("efmABC"),
    "long": {
        "--max-depth",
        "--threads",
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
    },
}
GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}


def _literal(value):
    """A flag value the guard can read as written: no expansion left in it."""
    return not any(c in value for c in "$`\\") and "\n" not in value


def _split_options(args, value_opts, take_optional=True):
    """(options as (name, value or None) pairs, positional words). Short groups such as `-rn`
    give one pair per letter; a value-taking letter takes the rest of the group or the next
    word. An "optional" option, or an abbreviation of a value-taking long option, takes the
    next word only when `take_optional`; callers use both readings."""
    optional = value_opts.get("optional", set()) if take_optional else set()
    value_opts = {
        "short": value_opts["short"] | {o[1] for o in optional if len(o) == 2},
        "long": value_opts["long"] | {o for o in optional if o.startswith("--")},
    }
    opts, pos, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos += args[i + 1 :]
            break
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if eq:
                opts.append((name, val))
            elif i + 1 < len(args) and (
                name in value_opts["long"]
                or (take_optional and any(_abbrev(name, f) for f in value_opts["long"]))
            ):
                opts.append((name, args[i + 1]))
                i += 1
            else:
                opts.append((name, None))
        elif a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                c = a[j]
                if c in value_opts["short"]:
                    rest = a[j + 1 :]
                    if rest:
                        opts.append(("-" + c, rest))
                    elif i + 1 < len(args):
                        opts.append(("-" + c, args[i + 1]))
                        i += 1
                    else:
                        opts.append(("-" + c, None))
                    break
                opts.append(("-" + c, None))
                j += 1
        else:
            pos.append(a)
        i += 1
    return opts, pos


def _abbrev(name, full, least=3):
    """True if `name` is `full` or an abbreviation of it that getopt-style parsers (GNU and
    BSD grep, git, ag) accept: a prefix with at least `least` letters after `--`. A prefix that
    another option shares is counted too, which can only widen the search."""
    return name.startswith("--") and len(name) - 2 >= least and full.startswith(name)


def _any_abbrev(names, fulls):
    return any(_abbrev(n, f) for n in names for f in fulls)


def _unwrap(words, bases):
    """Look through wrapper commands (`env`, `nice`, `timeout`, `xargs`, `sudo` ...) to the
    command they run. Returns (words, bases, through xargs?). The run command is the first
    later word that names a search tool; `env -C DIR` and `sudo -D DIR` change the folder."""
    via_xargs = False
    for _ in range(8):
        if not words or os.path.basename(words[0]).lower() not in WRAPPERS:
            break
        wrapper = os.path.basename(words[0]).lower()
        via_xargs = via_xargs or wrapper == "xargs"
        for i, w in enumerate(words[1:], 1):
            name, eq, val = w.partition("=")
            if (
                wrapper in ("env", "sudo")
                and name in ("-C", "--chdir", "-D")
                and i + 1 < len(words)
            ):
                bases = [expand(val if eq else words[i + 1], b) or b for b in bases]
        nxt = next(
            (
                i
                for i, w in enumerate(words[1:], 1)
                if os.path.basename(w).lower() in SEARCH_TOOLS
                or w == "git"
                or os.path.basename(w).lower() in WRAPPERS
            ),
            None,
        )
        if nxt is None:
            return [], bases, via_xargs
        words = words[nxt:]
    return words, bases, via_xargs


def search_targets(part, cwd, command="", folders=None):
    """SPEC 3b: the searches a command segment runs, as Search objects (a folder, and what
    grep's own options narrow). Only recursive searches; a folder that does not exist is left
    out. A search whose folders or files cannot be told is a Search that denies."""
    try:
        words = shlex.split(part, posix=True)
    except ValueError:
        words = part.split()
    while words and ("=" in words[0] and not words[0].startswith("-")):
        words = words[1:]  # leading VAR=value
    # Relative paths count from every folder the command may be in: the session's folder and
    # each one it changes into with `cd` or `pushd`.
    bases = list(dict.fromkeys(folders or [cwd]))
    words, bases, via_xargs = _unwrap(words, bases)
    if not words:
        return []
    prog = os.path.basename(words[0]).lower()
    args = words[1:]
    if prog == "git":
        i = 0
        while i < len(args) and args[i].startswith("-"):
            name, eq, val = args[i].partition("=")
            if name in GIT_VALUE_OPTS and not eq and i + 1 < len(args):
                if name == "-C":
                    bases = [expand(args[i + 1], b) or b for b in bases]
                i += 2
                continue
            if name == "-C" and eq:
                bases = [expand(val, b) or b for b in bases]
            i += 1
        if i >= len(args) or args[i] != "grep":
            return []
        prog, args = "git-grep", args[i + 1 :]
    if prog not in SEARCH_TOOLS:
        return []
    value_opts = {"rg": RG_VALUE_OPTS, "ag": AG_VALUE_OPTS, "git-grep": GIT_GREP_VALUE_OPTS}.get(
        prog, GREP_VALUE_OPTS
    )
    # Two readings: optional values and abbreviated value options take the next word, or do
    # not. The options and the paths of both count, so neither reading can hide a folder.
    opts, pos = _split_options(args, value_opts)
    opts2, pos2 = _split_options(args, value_opts, take_optional=False)
    readings = [pos, pos2]
    opts = opts + [o for o in opts2 if o not in opts]
    names = {n for n, _ in opts}
    includes, excludes, exclude_dirs = [], [], []
    if prog in ("grep", "egrep", "fgrep", "zgrep", "ugrep"):
        dir_recurse = any(
            (n == "-d" or _abbrev(n, "--directories")) and v == "recurse" for n, v in opts
        )
        recursive = bool(names & {"-r", "-R"}) or _any_abbrev(
            names, ("--recursive", "--dereference-recursive")
        )
        if not (dir_recurse or recursive):
            return []
        if prog != "ugrep":  # T5: grep's own narrowing, when written as a literal
            for n, v in opts:
                if v is None or not _literal(v) or "/" in v:
                    continue
                if n == "--include":
                    includes.append(v)
                elif n == "--exclude":
                    excludes.append(v)
                elif n == "--exclude-dir":
                    exclude_dirs.append(v)
    # With -e or -f the pattern is an option value, so every positional word is a path.
    pattern_in_opts = names & {"-e", "-f", "--regexp", "--file"}
    paths = []
    for words in readings:  # every reading of an optional value: walk the paths of each
        for p in (words if pattern_in_opts else words[1:]) or ["."]:
            if p not in paths:
                paths.append(p)
    if via_xargs:  # its folders come from input the hook cannot see
        return [Search(bases[0], reason=XARGS_SEARCH)]
    if prog == "git-grep":
        # git reads committed files for a revision and the index for --cached, which the walk
        # cannot list. Words before `--` (after the pattern) are revisions; a word that is
        # neither a folder nor a file is a revision or a pattern path.
        if _any_abbrev(names, ("--cached",)):
            return [Search(bases[0], reason=GIT_GREP_UNCHECKED)]
        if "--" in args:
            before = _split_options(args[: args.index("--")], value_opts)[1]
            if before if pattern_in_opts else before[1:]:
                return [Search(bases[0], reason=GIT_GREP_UNCHECKED)]
        for p in paths:
            if p != "." and not any(os.path.exists(expand(p, b) or "") for b in bases):
                return [Search(bases[0], reason=GIT_GREP_UNCHECKED)]
    out = []
    for p in paths:
        found = [expand(p, b) for b in bases]
        if any(c in p for c in "*?["):  # grep -r foo *: search what the pattern matches
            w = Word()
            w.chars = [(c, U if c in "*?[]" else Q) for c in p]
            found += word_paths(w, bases)
        for full in found:
            if full and not is_network(full) and os.path.isdir(full):
                out.append(Search(full, includes, excludes, exclude_dirs))
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


SCRIPT_CHARS = set(" \t\n;|&<>$`")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "yash"}
SHELL_RUNNERS = SHELLS | {"busybox", "su", "watch", "script"}
DASH_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*$")  # -c, -lc, -ec ...


def shell_scripts(sw, depth):
    """Text the shell reads again as a command (SPEC 3a G1 (b)), each with the values it is
    given: $(...), `...` and <(...); the string after -c for sh, bash, zsh, dash or ksh (also
    behind sudo, env, timeout, xargs or find -exec), whose next words become $0, $1 ...;
    every argument of eval, joined; and the strings in a pipeline that ends in a shell."""
    out = [(n, sw.env) for n in sw.nested]
    segs = sw.segments
    for k, seg in enumerate(segs):
        lits = [w.literal for w in seg]
        names = [os.path.basename(x).lower() for x in lits]
        for j, name in enumerate(names):
            if name == "eval":
                out.append((" ".join(lits[j + 1 :]), sw.env))
            if name not in SHELL_RUNNERS:
                continue
            flag = next((n for n in range(j + 1, len(lits)) if DASH_C.match(lits[n])), None)
            if flag is not None and flag + 1 < len(lits):
                args = lits[flag + 2 :]
                env = dict(sw.env)
                for n, v in enumerate(args):
                    env[str(n)] = [v]
                env["@"] = list(args[1:]) or [""]
                out.append((lits[flag + 1], env))
            out += [(x, sw.env) for x in lits[j + 1 :] if SCRIPT_CHARS & set(x)]
        # a pipeline that ends in a shell reading its script from the pipe
        if k > 0 and sw.pipes[k - 1] and any(n in SHELLS for n in names):
            if not any(DASH_C.match(x) for x in lits):
                start = k - 1
                while start > 0 and sw.pipes[start - 1]:
                    start -= 1
                for prev in segs[start:k]:
                    words = [w.literal for w in prev]
                    out.append((" ".join(words[1:]), sw.env))
                    out += [(x, sw.env) for x in words[1:]]
    if out and depth >= MAX_NESTING:
        raise HookTimeout("commands are nested too deeply to check")
    return out


HIDDEN_SWITCH_WORDS = ("dotglob", "globdots", "globignore", "bashopts")
OPTION_VERBS = {"shopt", "setopt", "unsetopt", "emulate"}
HIDDEN_MESSAGE = (
    "the command may turn on matching of hidden file names (dotglob, globdots, GLOBIGNORE), "
    "which denypeek's 'auto' setting relies on being off; do that in your own terminal, or "
    "run: denypeek guard install --hidden always"
)


def hidden_switch_problem(command, sw):
    """SPEC 3a G8, in `auto` only: deny anything that turns hidden-name matching on, or might."""
    text = re.sub(r"[\"'\\]", "", command).lower().replace("_", "")
    if any(k in text for k in HIDDEN_SWITCH_WORDS):  # (1), as written
        return HIDDEN_MESSAGE
    # (1) again, on the words as the shell finally sees them: line continuations joined,
    # $'...' decoded, variables given a literal value spliced in, braces expanded
    for w in sw.words():
        for chars in _brace_expand(list(w.chars)):
            flat = "".join(c for c, _ in chars).lower().replace("_", "")
            if any(k in flat for k in HIDDEN_SWITCH_WORDS):
                return HIDDEN_MESSAGE

    def opaque(w):
        return any(k == X for _, k in w.chars) or bool(set(w.literal) & set("$`"))

    for seg in sw.segments:
        lits = [w.literal for w in seg]
        names = [os.path.basename(x).lower() for x in lits]
        for j, name in enumerate(names):
            rest = seg[j + 1 :]
            # (2) zsh's one-letter option 4 is GLOB_DOTS: zsh -4, zsh -f4c, set -4, setopt -4
            if name in ("zsh", "set", "setopt", "unsetopt") and any(
                w.literal[:1] in "-+" and "4" in w.literal for w in rest
            ):
                return HIDDEN_MESSAGE
            # (3) an option-changing word whose option name is not a readable literal
            if name in OPTION_VERBS and any(opaque(w) for w in rest):
                return HIDDEN_MESSAGE
            if name == "set" or name in SHELLS:
                for n, w in enumerate(rest[:-1]):
                    if w.literal in ("-o", "+o", "-O", "+O") and opaque(rest[n + 1]):
                        return HIDDEN_MESSAGE
        for w in seg:
            if w.literal.startswith("options") and opaque(w):  # zsh options[$x]=on
                return HIDDEN_MESSAGE
        # (4) setting a variable whose name is not a readable literal: it could be GLOBIGNORE
        if _sets_unreadable_name(seg, opaque):
            return HIDDEN_MESSAGE
    return None


DECLARE_VERBS = {"declare", "typeset", "export", "readonly", "local"}


def _sets_unreadable_name(seg, opaque):
    """`${n}IGNORE=x`, `declare ${n}IGNORE=x`, `printf -v ${n}IGNORE x`, `read $n` ..."""

    def unreadable_name(w):
        chars = w.chars
        eq = next((n for n, (c, k) in enumerate(chars) if c == "=" and k == U), len(chars))
        head = Word()
        head.chars = chars[:eq]
        return opaque(head)

    lits = [w.literal for w in seg]
    names = [os.path.basename(x).lower() for x in lits]
    for w in seg:
        if w.cmdpos and any(c == "=" and k == U for c, k in w.chars) and unreadable_name(w):
            return True
    for j, name in enumerate(names):
        rest = seg[j + 1 :]
        if name in DECLARE_VERBS:
            if any(not x.literal.startswith(("-", "+")) and unreadable_name(x) for x in rest):
                return True
        elif name == "printf":
            for n, x in enumerate(rest[:-1]):
                if x.literal == "-v" and opaque(rest[n + 1]):
                    return True
        elif name == "read":
            if any(not x.literal.startswith("-") and opaque(x) for x in rest):
                return True
    return False


def _skip_word(w):
    return w.cmdpos and w.literal in ("[", "[[", "]]")


def _literal_hits(token, folder, rules):
    """Blocked paths a token names as written, with {a,b} braces and a leading `@`."""
    found = []
    for chars in _brace_expand([(c, U if c in "{},." else Q) for c in token]):
        variant = "".join(c for c, _ in chars)
        for v in (variant, variant[1:] if variant.startswith("@") else ""):
            full = expand(v, folder) if v else None
            if full and blocked_path(full, rules):
                found.append(full)
    return found


def check_command(command, cwd, rules, deadline, depth=0, extra=(), globs=True, env=None):
    """`globs`: read the command as the shell would (SPEC 3a). False for text that is only
    data to its program, such as python3 -c '...': there only names written out count."""
    tokens, parts = split_tokens(command)
    sw = shell_words(command, cwd, env)
    words = sw.words()
    if switches_guard(tokens) or switches_guard([w.literal for w in words]):
        return (
            "denypeek guard install and uninstall change the guard itself; "
            "run them yourself in a terminal"
        )
    # `cd dir && cat .env`: relative paths are checked against every folder the command
    # changes into, as well as the starting one.
    folders = [cwd] + list(extra) + cd_targets(parts, cwd)
    if len(words) > MAX_TOKENS or len(tokens) > MAX_TOKENS:
        raise HookTimeout("the command has too many words to check")
    if hidden_names() == "auto":
        problem = hidden_switch_problem(command, sw)
        if problem:
            return problem
    # 1. names written out, in any word or quoted text (G5, as written)
    for tok in tokens:
        tick()
        if depth < MAX_NESTING and SCRIPT_CHARS & set(tok):
            reason = check_command(tok, cwd, rules, deadline, depth + 1, extra, globs=False)
            if reason:
                return reason
            continue
        for folder in folders:
            hits = _literal_hits(tok, folder, rules)
            if hits:
                return reason_for(hits[0], "names")
    if globs:
        # 2. what the shell can expand each word to (G1 to G6)
        for script, script_env in shell_scripts(sw, depth):
            reason = check_command(script, cwd, rules, deadline, depth + 1, extra, env=script_env)
            if reason:
                return reason
        for w in words:
            tick()
            if _skip_word(w):
                continue
            for path in word_paths(w, folders):
                if blocked_path(path, rules):
                    if not is_protected(path):
                        hidden = hidden_only_reason(w, folders, rules)
                        if hidden:
                            return hidden
                    return reason_for(path, "names")
    for part in parts:
        for search in search_targets(part, cwd, command, folders):
            reason = search_tree(search, rules, deadline)
            if reason:
                return reason
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
            moving = any(w in tool.lower() for w in ("delete", "remove", "move", "rename"))
            if is_path_key(key) and moving and is_agent_dir(expand(s, folder)):
                return "deleting or moving an agent's settings folder would remove the hook"
            if is_path_key(key) and moving and is_ancestor(expand(s, folder)):
                return ANCESTOR_MESSAGE  # G7: Cursor's Delete on the home folder
            if is_path_key(key):
                problem = settings_edit_problem(expand(s, folder) or "", tool_input)
                if problem:
                    return problem
        if tool in MANY_FILE_TOOLS:
            # Gemini read_many_files reads whole folders and recursive globs (G8)
            base = s.split("**", 1)[0] if "**" in s else s
            folder = expand(base or ".", cwd)
            if folder and not is_network(folder) and os.path.isdir(folder):
                reason = search_tree(Search(folder), rules, deadline)
                if reason:
                    return reason
        if tool in GREP_TOOLS and key in ("path", "dir_path"):
            folder = expand(s, cwd)
            if folder and not is_network(folder) and os.path.isdir(folder):
                # T1: the agents' own search tools are class I until their defaults are known
                reason = search_tree(Search(folder), rules, deadline)
                if reason:
                    return reason
    if (
        tool in GREP_TOOLS
        and isinstance(tool_input, dict)
        and not (tool_input.get("path") or tool_input.get("dir_path"))
    ):
        reason = search_tree(Search(cwd), rules, deadline)
        if reason:
            return reason
    return None


# --- agent formats -------------------------------------------------------------------


def deny_output(agent, event_name, reason):
    """(stdout, exit code) that each agent reads as a denial."""
    msg = f"denypeek blocked this: {reason}."
    if (
        reason not in (HIDDEN_GLOB_REASON, TREE_TOO_BIG)
        and "denypeek protects" not in reason
        and not reason.endswith(TIMEOUT_ADVICE)
        and not reason.startswith(TREE_SECRET)
    ):
        msg += " If this is wrong, edit ~/.denypeek/secretfiles."
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
        # A decision that ran out of time is a normal denial, sent the way each agent shows a
        # block (Claude Code labels exit 2 as a "hook error"). Crashes and bad input still exit
        # 2: there the output itself may not be trusted, and exit 2 blocks on its own.
        reason = f"{exc}, so the guard could not decide in time; {TIMEOUT_ADVICE}"
        out, code = deny_output(agent, event.get("hook_event_name"), reason)
        return out, code, reason
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
