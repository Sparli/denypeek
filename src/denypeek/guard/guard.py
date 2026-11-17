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


def shell_settings_problem(command, folders, depth=0):
    """Shell commands may read agent settings files but not write them, and may not use an
    agent settings folder itself as the source or target of a change (R2): `cp x .claude/`,
    `mv dir .claude`, `tar -C .claude`, `dd of=.claude/settings.json`."""
    for raw in SHELL_OPERATORS.split(command):
        for target in REDIRECT_TARGET.findall(raw):
            if any(settings_kind(expand(target, f) or "") for f in folders):
                return "the command writes an agent settings file; edit it in your own terminal"
    sw = shell_words(command, folders[0] if folders else ".")
    for script in shell_scripts(sw, depth):
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


def shell_folder_problem(command, folders, depth=0):
    message = (
        "the command may move, delete or change an agent's settings folder, which "
        "would remove the denypeek hook; do that in your own terminal"
    )
    sw = shell_words(command, folders[0] if folders else ".")
    for script in shell_scripts(sw, depth):
        if shell_folder_problem(script, folders, depth + 1):
            return message
    for seg in sw.segments:
        words = [w for w in seg if not _skip_word(w)]
        while words and _is_assignment(words[0]) != -1:
            words = words[1:]
        if not words:
            continue
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
    return shlex.quote(_ansi_c_text(match.group(1)))


# --- shell words: SPEC section 3a, the shell-word rule ------------------------------------
# One lexer reads a command into words whose characters are tagged unquoted ("u") or quoted
# ("q"). Only unquoted characters can be glob syntax (G1). A literal value put into an
# unquoted $name counts as unquoted; values are data, so they never open quotes, start
# comments or end commands. Each word is then checked twice (G5): as written, and widened
# into a pattern that matches at least every path bash, zsh or sh could reach with it.

U, Q = "u", "q"
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
    __slots__ = ("segments", "nested")

    def __init__(self):
        self.segments = []  # list of list[Word], one per simple command
        self.nested = []  # command text inside $(...), `...`, <(...), >(...), =(...)

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
    def __init__(self, text, cwd, home, env):
        self.s, self.cwd, self.home, self.env = text, cwd, home, env
        self.out = ShellWords()
        self.seg, self.word = [], None
        self.cmdpos, self.array = True, 0
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
        eq = _is_assignment(w)
        if eq != -1:
            self.env[w.literal[:eq].split("[")[0]] = [c for c, _ in w.chars[eq + 1 :]]
            return  # an assignment keeps command position
        lit = w.literal
        if w.cmdpos and (
            lit in CMD_KEYWORDS or lit in ("export", "local", "readonly", "declare", "typeset")
        ):
            return
        if not self.array:
            self.cmdpos = False

    def _end_segment(self):
        self._end_word()
        if self.seg:
            self.out.segments.append(self.seg)
        self.seg, self.cmdpos = [], True

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
            value = self.env.get(name)
        if value is not None:
            self._start()
            self._splice(value, quoted)
        else:
            self._start()  # unknown: run-time text (known miss 2); the word still exists

    def _nested(self, i, open_ch, close_ch):
        end = _matching(self.s, i, open_ch, close_ch)
        if end == -1:
            self.out.nested.append(self.s[i + 1 :])
            return len(self.s)
        self.out.nested.append(self.s[i + 1 : end])
        self._start()
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
            self._start()
            return len(s) if end == -1 else end + 1  # arithmetic: run-time text
        if nxt == "(":
            return self._nested(i + 1, "(", ")")
        if nxt == "{":
            end = _matching(s, i + 1, "{", "}")
            if end == -1:
                self._add("$", Q if quoted else U)
                return i + 1
            body = s[i + 2 : end].lstrip("~=^")  # zsh ${~x}, ${=x}, ${^x}
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(:?[-=+])?(.*)", body, re.S)
            if m and not m.group(2) and not m.group(3):
                self._variable(m.group(1), quoted)
            elif m and m.group(2) and m.group(2).lstrip(":") in "-=":
                # ${x:-word}: when x is unset the shell uses `word`; check that reading too
                sub = _Lexer(m.group(3), self.cwd, self.home, self.env)
                sub.run()
                for w in sub.out.words():
                    self._splice(w.literal, quoted)
                self.out.nested.extend(sub.out.nested)
            else:
                self._start()  # ${#x}, ${x#p}, ${x^^}, ${x[1]}: run-time text
            return end + 1
        m = re.match(r"[~=^]*([A-Za-z_][A-Za-z0-9_]*)", s[i + 1 :])  # zsh $~x, $=x, $^x
        if m:
            self._variable(m.group(1), quoted)
            return i + 1 + m.end()
        if nxt and (nxt.isdigit() or nxt in "#?@*$!-"):
            self._start()  # $1, $#, $?, $@ ...: run-time text
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
            elif c in "\n;&|":
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
                self._start()
                i = end + 1
            elif c == "<" and NUMERIC_RANGE.match(s, i):
                end = NUMERIC_RANGE.match(s, i).end()
                for ch in s[i:end]:
                    self._add(ch, U)  # zsh <1-99> and <->: a pattern, not a redirection
                i = end
            elif c in "<>":
                if i + 1 < len(s) and s[i + 1] == "(":
                    i = self._nested(i + 1, "(", ")")  # process substitution
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
            self._end_word_keep_array()
            return i + 1
        if w is None and self.cmdpos and not self.array:
            self._end_segment()  # a subshell: (cd src && ls)
            return i + 1
        # An unquoted `(` in an argument: a glob group in zsh, or after @ + ! ? * in
        # extglob. Keep it and everything up to its balancing `)` in the word.
        end = _matching(self.s, i, "(", ")")
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


def shell_words(command, cwd, env=None):
    """Lex a command (SPEC 3a G1). Raises HookTimeout on runaway input."""
    text = unicodedata.normalize("NFC", command)
    text = text.replace("\\\r\n", "").replace("\\\n", "")
    text = windows_paths(text)
    lexer = _Lexer(text, cwd, home_dir(), {} if env is None else env)
    return lexer.run()


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
    if c in "@+!?*" and nxt == ("(", U):
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


def widen(chars):
    """The widened pattern of a word (G2, G3): a list of path parts, each ("lit", text),
    ("pat", regex) or ("any", regex-or-None), and a flag: the last part also stands for
    everything under it (G3c). None if the word holds no glob syntax."""
    if not _has_glob(chars):
        return None
    # G3b: an unquoted `~` that is not at the start of the word cuts the whole word
    for n in range(1, len(chars)):
        if chars[n] == ("~", U) and chars[n - 1][0] not in "=:":
            chars = chars[:n]
            break
    parts, cur, tree = [], [], False
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
        first_dot = toks[0][0] == "lit" and toks[0][1] == "."
        if any(
            t == ("star", ".*") and n + 1 < len(toks) and toks[n + 1] == ("star", ".*")
            for n, t in enumerate(toks)
        ):
            parts.append(("any", None if rx == ".*.*" else rx, first_dot))
        else:
            parts.append(("pat", rx, first_dot))

    while i < len(chars):
        c, k = chars[i]
        if c == "/":
            close_part()
            cur = []
            i += 1
            continue
        if k == U and c == "[":
            if _closes_after_slash(chars, i, "[", "]"):
                cur.append(("star", ".*"))
                tree = True
                break
            end = _bracket_close(chars, i)
            cur.append(("one", "."))
            i = end + 1 if end != -1 else i + 1
            continue
        if k == U and c in OPERATOR_CHARS | set("@+!?*") and _operator_at(chars, i):
            open_ch = "(" if c in "@+!?*" else c
            close_ch = {"(": ")", "{": "}", "<": ">"}.get(open_ch)
            if close_ch and _closes_after_slash(chars, i, open_ch, close_ch):
                cur.append(("star", ".*"))
                tree = True
                break
            if c == "#" and cur:
                cur.pop()  # G3a: `#` repeats the unit before it, which may be absent
            cur.append(("star", ".*"))
            while i < len(chars) and chars[i][0] != "/":
                i += 1
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
    try:
        with os.scandir(folder) as it:
            names = []
            for e in it:
                budget.spend()
                names.append(e.name)
            return names
    except OSError:
        return []


def _descendants(path, budget, include_self=True):
    out = [path] if include_self else []
    stack = [path]
    while stack:
        d = stack.pop()
        if not os.path.isdir(d) or os.path.islink(d) and d != path:
            continue
        for n in _entries(d, budget):
            p = os.path.join(d, n)
            out.append(p)
            if os.path.isdir(p) and not os.path.islink(p):
                stack.append(p)
    return out


def walk_pattern(bases, parts, tree, budget):
    """Every existing path the widened pattern can reach from the base folders."""
    cur = list(dict.fromkeys(bases))
    for n, part in enumerate(parts):
        kind = part[0]
        nxt = []
        if kind == "lit":
            nxt = [os.path.join(d, part[1]) if part[1] else d for d in cur]
        else:
            rx = part[1]
            first_dot = part[2]
            if kind == "any":
                dirs = []
                for d in cur:
                    dirs += [p for p in _descendants(d, budget) if os.path.isdir(p)]
                if rx is None:  # a part that is exactly `**`
                    if n == len(parts) - 1:
                        for d in cur:
                            nxt += _descendants(d, budget)
                    else:
                        nxt = dirs
                    cur = list(dict.fromkeys(nxt))
                    continue
                cur = dirs
            pat = re.compile(rx.replace(".*.*", ".*"), re.S | re.I)
            for d in cur:
                names = _entries(d, budget)
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


SCRIPT_CHARS = set(" \t\n;|&<>$`")
SHELL_RUNNERS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "yash",
    "busybox",
    "eval",
    "su",
    "watch",
    "script",
}


def shell_scripts(sw, depth):
    """Text the shell itself reads again as a command (SPEC 3a): $(...), `...`, <(...), and
    words given to sh -c, bash -c, zsh -c, eval and similar. Other quoted text is data."""
    out = list(sw.nested)
    for seg in sw.segments:
        runner = False
        for w in seg:
            lit = w.literal
            if runner and SCRIPT_CHARS & set(lit):
                out.append(lit)
            if os.path.basename(lit).lower() in SHELL_RUNNERS:
                runner = True
    if out and depth >= MAX_NESTING:
        raise HookTimeout("commands are nested too deeply to check")
    return out


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


def check_command(command, cwd, rules, deadline, depth=0, extra=(), globs=True):
    """`globs`: read the command as the shell would (SPEC 3a). False for text that is only
    data to its program, such as python3 -c '...': there only names written out count."""
    tokens, parts = split_tokens(command)
    sw = shell_words(command, cwd)
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
        for script in shell_scripts(sw, depth):
            reason = check_command(script, cwd, rules, deadline, depth + 1, extra)
            if reason:
                return reason
        for w in words:
            tick()
            if _skip_word(w):
                continue
            for path in word_paths(w, folders):
                if blocked_path(path, rules):
                    return reason_for(path, "names")
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
