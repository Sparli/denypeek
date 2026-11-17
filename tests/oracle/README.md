# Glob oracle for the denypeek guard

Owner: security review. This is the acceptance test for SPEC section 3a (tests A23 to A25). It is adopted
into `tests/` and CI. Until then, this folder is the reference. The security review owns the word list and the
must-allow list; removing a must-allow command needs a spec ruling (A25).

The real shells decide. Each test word is expanded by bash, zsh and sh in a throwaway fixture
home. If any shell reaches a protected path with it, the hook must deny the command. A fixed list
of ordinary developer commands must be allowed.

## Files

- `glob_oracle.py`: the runner. Python 3.9+, standard library only.
- `words.tsv`: 3,242 generated words (target, mutation class, word, command, working folder
  relative to the fixture home; empty means the home folder itself). Expectations are not
  stored. They are computed on every run from the shells on that machine, because bash 3.2, bash 5,
  zsh and dash differ.

## Run

```bash
python3 glob_oracle.py --hook ../repo/src/denypeek/guard/guard.py --python /usr/bin/python3 --require auto
```

```bash
python3 glob_oracle.py --self-test
```

- `--hook PATH`:
  - a `guard.py` is run as `PYTHON -I -S guard.py --agent claude --home <fixture>`;
  - any other executable is run as `PATH --agent claude`, plus `--home <fixture>` with `--hook-takes-home`.

  An installed `guard.sh` has its own home written into it, so test `guard.py` directly.
  `--hook` reads the file as it is on disk. To measure a commit rather than uncommitted work,
  extract it first: `git show <commit>:src/denypeek/guard/guard.py > /tmp/guard-<commit>.py`.
- `--python`: the Python a `guard.py` hook runs with. Run once with `/usr/bin/python3` (3.9 on
  macOS) and once with a current Python.
- `--quick`: one word per mutation class instead of the full list.
- `--require auto` (or a list such as `bash3,bash5,zsh,sh`): **always use this for A23 to A25.** With it, a missing shell family, a mode that cannot be set up, or a named or sentinel case with no available mode is a failure, not a skip (A25). `auto` means bash3, bash5, zsh and sh on macOS, and bash5, zsh and sh elsewhere (bash 3.2 exists only on macOS). Without `--require`, these are skips, listed in the RESULT line. A failed precondition is always a failure.
- `--report FILE`: write every failure, one per line.
- `--self-test`: two controls, checked tier by tier. The allow-all hook must fail every must-block tier and pass must-allow; the deny-all hook the mirror. Any other result means the oracle is broken.
- `--write-words words.tsv`: regenerate the list after changing the generator.
- `--keep`: keep the fixture home for debugging.
- `--hidden always|auto`: the SPEC 3a G8 setting under test. For `auto`, the fixture writes
  `{"hidden_names": "auto"}` to `~/.denypeek/guard-state.json`; `always` writes nothing, because
  a missing setting means `always`. **A23 to A25 need two full runs, one per setting**, each on
  both Pythons. In `auto`, modes that turn dotglob or globdots on are not required (known miss
  7); they still run when present, and their setup line is then a switch the hook must catch.

Exit 0 means all passed, 1 means a failure, 2 means a usage or environment problem.

## Tiers

1. **NAMED**: L1, L2, N1 to N7, the spec's H1 to H6 and one word each for G3b, G3c and zsh
   `globstarshort`, each with the shell mode it needs and its working folder. A named case first checks
   that this shell really reaches the target, and fails loudly if not. A pass therefore cannot
   come from a shell that never expanded the word.
2. **GENERATED**: every word in `words.tsv`, under every available mode. Most words change one
   character class at a time. 840 `combo:` words, seeded and so reproducible, change two or three
   in one name, across 23 targets, some behind a folder prefix. They were added after fresh
   combination words found C1 and C2, where each feature alone was denied but the combination
   was not. A pair that reaches a
   protected path must be denied. Failures are grouped by mutation class.
3. **SENTINEL**: commands that really run, but only `cat` of fixture files. They cover globs that
   are quoted first and expanded later: variables, arrays, `set --`, `for`, command
   substitution, `bash -c`, `sh -c`, `zsh -c` and `eval`, and G1's value-used-unquoted cases
   (`a='.e*'; cat $a`, zsh `cat $~a`). It also covers the spec's seven G1 cases from
   `5b03394`, where quoted text is read again by a shell:
   - `for f in '.e*'; do cat $f; done`, `set -- '.e*'; cat $1`, `a=('.e*'); cat ${a[0]}`;
   - `sh -c 'cat $0' '.e*'`, `eval cat '.e*'`, `eval cat .e\*`;
   - `echo 'cat .e*' | sh`.

   If the shell did not print a protected file's sentinel, the precondition failed, which is a
   failure.
4. **ANCESTOR** (G7): 32 must-block commands that delete, move or lock the home folder or a folder
   above it.
   - **Covered:** `rm`, `rmdir`, `unlink`, `shred`, `trash`; `sudo`, `env`, `/bin/rm` and `\rm` forms; `mv` and `mv -t`; `chmod`, `chown`, `chgrp` and `chflags`; `git clean` (from home, `-C ~`, `cd ~ &&`); `rsync --delete…` and `--remove-source-files`; `find ~ -delete` and `-exec`; and Cursor's `Delete` tool on the home folder.
   - **Never run:** the precondition only expands the operand with `printf` and checks that it resolves to the home folder or above.
5. **MUST-ALLOW**: 81 ordinary commands (91 under `auto`). They include `cat app/[lang]/[id]/page.tsx`,
   `ls */`, `ls -d */`, `ls */README.md`, `rm -rf */__pycache__`, `cat ~/.ssh/id_ed25519.pub` and `cat ~/.ssh/*.pub`, which the spec ruled on 2026-11-17, plus, run in a folder that holds `.env`, including every
   command in SPEC section 3a "What must stay allowed" and its G7 list (`mv notes.md ~`,
   `ls ..`, `cd ~ && ls`, `chmod +x ~/bin/tool`, `rm -rf .*_cache`, `git clean -fd` in a project,
   `find ~ -name x` and others).
6. **G8** (hidden names).
   - **`always`:** the five bare-`*` commands (`du -sh *`, `cat *`, `wc -l *`, `grep foo *`, `rm -rf ./*`) must be denied.
   - **`auto`:** the switch forms must be denied. Each first runs for real in `proj/g8`, which holds `.env`, `sub/.env` and plain files, and must print a hidden file's sentinel.
     - **the spec's 24 forms (`H-`):** a failed precondition is a failure.
     - **the review's attack forms (`V-`):** a form that does not work in that shell is reported, not failed.
     - **Four other must-blocks:** `grep -r foo *` beside `sub/.env`, `rm -rf *` from the folder above home, `x=.; cat $x*`, `cat *(D)`.
     - **Must-allow:** the five bare-`*` commands plus `set -euo pipefail; ls *`, `shopt -s nullglob; ls *.py`, `setopt extendedglob; ls *.py`, `ls *`, `echo *`.
7. **INFORMATIONAL**: reported, not asserted: SPEC 3a's accepted over-blocks (`ls (src|tests)`,
   `grep ^foo`, `echo C#`, a pattern in `[[ … ]]`, `ls .*`, `ls .e*`, `rg TODO .`, and under G7
   `chmod 700 ~` and `grep -r rm ~`).

## Shell modes and the options each case needs

| Family | Shell | Modes (setup line in the command) |
|---|---|---|
| bash3 | a bash 3.x (`/bin/bash` on macOS) | default, `extglob`, `nocaseglob`, `dotglob`, `dotglob extglob` |
| bash5 | a bash 4+ (Homebrew on macOS, `/bin/bash` on Linux) | the same, plus `globstar`, `globstar dotglob` |
| zsh | zsh | default, `extendedglob`, `kshglob`, `nocaseglob`, `globdots`, `globstarshort`, `extendedglob globdots` |
| sh | `/bin/sh` (bash 3.2 in POSIX mode on macOS, dash on Debian and Ubuntu) | default |

A case names its mode as a spec such as `bash5|bash3`: the first available mode is used.

The setup line is part of the command the hook sees, because an agent can send it too. A mode
whose binary is missing, or whose setup line fails, is skipped and reported; under `--require`
that is a failure for a required family. A user's own rc files can turn these options on without any setup line, so the guard
must not rely on seeing it.

**Named cases:**
- **L1:** `[!z-a]`, `[^z-a]`. Default bash and zsh.
- **L2:** `[^x]`. Default bash and zsh.
- **N1:** `!(#)`. Needs extglob or kshglob.
- **N2:** brackets with `/`. Default zsh.
- **N3:** `{....}`. Default zsh.
- **N4:** groups and repeats.
  - default zsh: `(x)`, `(x|y)`;
  - extendedglob: `x#`, `(#i)`;
  - extglob: `@(x)`.
- **N5:** `(#a1)`. Needs extendedglob.
- **N6:** `$'…'` in an agent-folder path. Every shell, no options.
- **N7:** zsh numeric ranges, `cert.p<->` and `id_ed<->`. Default zsh.
- **H1, H2 (G4):** `~+` from the home folder: `rm -rf ~+/.denypeek` (bash, sh), `cat ~+/.denypeek/secretfiles` (zsh).
- **H3 (G3a):** `cat .env[x]#`, zsh extendedglob, in a folder that holds only `.env`.
- **H4 to H6 (G2):** `.` and `..` matches, bash 3.2 or `/bin/sh`: `cat .*/.en?`, `cat .?/.en?` from
  a subfolder, and `rm -rf ~/.claude/.?/.denypeek`.
- **G3b, G3c:**
  - `cat .e*~*/q` (zsh extendedglob);
  - `cat (x/)#.env` (zsh extendedglob);
  - `cat .e[!]/]v` (default zsh).
- **GS:** `cat **.pem` with zsh `globstarshort`.
- **C1:** `cat ~/.gemini/se(t)tings.[^/]son`, default zsh: a group and a bracket holding `/`, behind a folder prefix.
- **C2:** `cat .e##[^/][^x]`, zsh extendedglob: a repeat, a bracket holding `/`, then another bracket.

## Safety

- **Real pattern file:** the fixture home holds `~/.denypeek/secretfiles` with the guard's default list, copied into the oracle (`DEFAULT_SECRETFILES`, byte-identical to `54f8d31`: `!*.pub` last), as a real install does. The SENTINEL tier checks `~/.ssh`: private keys, `~/.ssh/*` and `known_hosts` must be denied; public keys pass. The installer is never run, so the oracle can judge any commit's hook on its own. If the default list changes, update that constant.
- **Temp fixture only:** the fixture home is created under the system temp folder and deleted afterwards. The script refuses a temp folder under the real home.
- **No real paths:** every shell and the hook get `HOME=<fixture>` and `PATH=/usr/bin:/bin`. The guard also gets `--home <fixture>`.
- **Nothing is deleted, moved or locked:** `rm`, `mv` and every G7 command are only judged by the hook. Their operands are expanded with `printf` and never run. Only the SENTINEL tier runs commands, and those only `cat` fixture files, through `sh -c`, `eval` or a pipe into `sh`.
- **No hangs:** stdin is closed and every process has a timeout.
- **Errors count as failures:** a hook crash, a timeout or an exit code other than 0 or 2 is ERROR, which is a failure in every tier, because Claude Code treats a non-2 error as allow.

## Hook contract checked

The Claude Code PreToolUse Bash event, plus one Cursor `preToolUse` `Delete` event (run with
`--agent cursor`, judged by Cursor's `{"permission": …}` reply). The glob logic is shared by all
four agents, so one agent shape is enough for the words. The per-agent event shapes are covered by the existing tests.

## Quoting rule the guard must follow

Quoted glob characters are literal, so `grep -o '[a-z]*' README.md` and `echo '*'` must be
allowed (SPEC 3a). There are three exceptions, now all in SPEC G1, and the SENTINEL tier checks
each one:
1. a string given to `sh -c`, `bash -c` or `zsh -c`;
2. the arguments of `eval`, joined, with quotes and backslashes removed (`eval cat '.e*'`);
3. a quoted value stored in a variable, an array element, a `for … in` list, `set --` or the arguments after a `-c` script, and later used unquoted (`a='.e*'; cat $a`);
4. a quoted string in a pipeline that ends in a shell with no script file (`echo 'cat .e*' | sh`).

Quoting is judged where the value is used, not where it is written.

## Limits

- **One machine so far:** run only on this Mac (bash 3.2.57, bash 5.3.9, zsh 5.9; `/bin/sh` is bash 3.2), at `f4bb7c0` and with the control hooks. Named-case preconditions are hard failures and have not been tried on Linux bash or on dash. If a named case fails its precondition there, check the shell before the guard.
- **Windows:** with no shells at all it exits 2, not a clean skip. CI should skip this on Windows and install zsh and bash 4+ on Linux and macOS.
- **Choices, not facts:** `ls (src|tests)` is informational by my choice; whether to allow it is a spec decision.
- **Not covered:** shells other than bash, zsh and sh (fish, ksh). Live agents.
