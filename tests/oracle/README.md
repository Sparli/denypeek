# Glob oracle for the denypeek guard

Owner: security review. This is the acceptance test for SPEC section 3a (tests A23 to A25). It is adopted
into `tests/` and CI. Until then, this folder is the reference. The security review owns the word list and the
must-allow list; removing a must-allow command needs a spec ruling (A25).

The real shells decide. Each test word is expanded by bash, zsh and sh in a throwaway fixture
home. If any shell reaches a protected path with it, the hook must deny the command. A fixed list
of ordinary developer commands must be allowed.

## Files

- `glob_oracle.py`: the runner. Python 3.9+, standard library only.
- `words.tsv`: 2,327 generated words (target, mutation class, word, command, working folder
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

Exit 0 means all passed, 1 means a failure, 2 means a usage or environment problem.

## Tiers

1. **NAMED**: L1, L2, N1 to N7, the spec's H1 to H6 and one word each for G3b, G3c and zsh
   `globstarshort`, each with the shell mode it needs and its working folder. A named case first checks
   that this shell really reaches the target, and fails loudly if not. A pass therefore cannot
   come from a shell that never expanded the word.
2. **GENERATED**: every word in `words.tsv`, under every available mode. A pair that reaches a
   protected path must be denied. Failures are grouped by mutation class.
3. **SENTINEL**: commands that really run, but only `cat` of fixture files. They cover globs that
   are quoted first and expanded later: variables, arrays, `set --`, `for`, command
   substitution, `bash -c`, `sh -c`, `zsh -c` and `eval`, and G1's value-used-unquoted cases
   (`a='.e*'; cat $a`, zsh `cat $~a`). If the shell did not print a protected file's sentinel,
   the precondition failed, which is a failure.
4. **MUST-ALLOW**: 65 ordinary commands, run in a folder that holds `.env`, including every
   command in SPEC section 3a "What must stay allowed".
5. **INFORMATIONAL**: reported, not asserted. SPEC 3a's accepted over-blocks (`ls (src|tests)`,
   `grep ^foo`, `echo C#`, a pattern in `[[ … ]]`, `ls .*`, `ls .e*`, `rg TODO .`), plus deletes or
   moves of an ancestor of the protected folders (`rm -rf ..`, `rm -rf ~`), which 3a does not
   yet cover.

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
- **H1, H2 (G4):** `~+` from the home folder: `rm -rf ~+/.denypeek` (bash, sh), `cat ~+/.denypeek/guard.sh` (zsh).
  the spec's case reads `secretfiles`. The fixture has none, because the guard then uses its
  built-in defaults, so the read aims at another file in the same folder.
- **H3 (G3a):** `cat .env[x]#`, zsh extendedglob, in a folder that holds only `.env`.
- **H4 to H6 (G2):** `.` and `..` matches, bash 3.2 or `/bin/sh`: `cat .*/.en?`, `cat .?/.en?` from
  a subfolder, and `rm -rf ~/.claude/.?/.denypeek`.
- **G3b, G3c:**
  - `cat .e*~*/q` (zsh extendedglob);
  - `cat (x/)#.env` (zsh extendedglob);
  - `cat .e[!]/]v` (default zsh).
- **GS:** `cat **.pem` with zsh `globstarshort`.

## Safety

- **Temp fixture only:** the fixture home is created under the system temp folder and deleted afterwards. The script refuses a temp folder under the real home.
- **No real paths:** every shell and the hook get `HOME=<fixture>` and `PATH=/usr/bin:/bin`. The guard also gets `--home <fixture>`.
- **Nothing is deleted or moved:** `rm` and `mv` words are only expanded with `printf`, never run. Only the SENTINEL tier runs commands, and those only `cat` fixture files.
- **No hangs:** stdin is closed and every process has a timeout.
- **Errors count as failures:** a hook crash, a timeout or an exit code other than 0 or 2 is ERROR, which is a failure in every tier, because Claude Code treats a non-2 error as allow.

## Hook contract checked

The Claude Code PreToolUse Bash event. The glob logic is shared by all four agents, so one agent
shape is enough here. The per-agent event shapes are covered by the existing tests.

## Quoting rule the guard must follow

Quoted glob characters are literal, so `grep -o '[a-z]*' README.md` and `echo '*'` must be
allowed (SPEC 3a). There are three exceptions, and the SENTINEL tier checks each one. Item 3 is
SPEC G1; items 1 and 2 are not yet written in SPEC 3a (raised with the spec):
1. a string given to `sh -c`, `bash -c` or `zsh -c`;
2. a string given to `eval`;
3. a quoted value stored in a variable or array and later used unquoted (`a='.e*'; cat $a`).

Quoting is judged where the value is used, not where it is written.

## Limits

- **One machine so far:** run only on this Mac (bash 3.2.57, bash 5.3.9, zsh 5.9; `/bin/sh` is bash 3.2), at `f4bb7c0` and with the control hooks. Named-case preconditions are hard failures and have not been tried on Linux bash or on dash. If a named case fails its precondition there, check the shell before the guard.
- **Windows:** with no shells at all it exits 2, not a clean skip. CI should skip this on Windows and install zsh and bash 4+ on Linux and macOS.
- **Choices, not facts:** `ls (src|tests)` is informational by my choice; whether to allow it is a spec decision.
- **Not covered:** shells other than bash, zsh and sh (fish, ksh). Live agents.
