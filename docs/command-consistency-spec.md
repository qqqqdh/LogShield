# Command consistency — 2026-11-03

Scope: make command roles consistent across main and the LLM branch. Preserve existing monitoring logic and feature differences; do not merge branches or change model processing. No production data generation, remote pushes or new dependencies.

## Final interface

- Both branches: cmd/loggen generates synthetic auth.log, ssh.log, web.log. Flags: -out ./sample-logs, -count 100 per file, -force false. -out is an output directory, not an alias of the monitor's input -log-dir.
- Both branches: cmd/logshield-tui monitors actual *.log files. Existing -log-dir ./logs and -alerts-file alerts.jsonl stay identical.
- main only: existing synthetic display demo moves intact to cmd/logshield-demo.
- Main monitoring implementation and its tests move intact from cmd/loggen to cmd/logshield-tui, preserving pause retention, resume order, journal and report saving. The LLM branch's existing monitoring TUI stays intact.
- Old main loggen -log-dir/-alerts-file invocations fail at flag parsing instead of generating files. Document migration.
- Existing logshield, logaudit, benchmark and LLM-specific options remain as they are.

## Dependency-order goals: route / output / parent check

1. Parent inline: status/diff, source/callers/tests, baseline suites. Write behavioral acceptance tests and show focused red before implementation.
2. Background codex, mechanical only: after parent tests are recorded, move exactly the 3 main files (demo source, monitor source, monitor tests) to their approved paths with git mv. No content edits, commits or tests. Parent independently compares pre/post file hashes and opens every moved file.
3. Parent inline: improve the LLM generator with standard exclusive creation, positive count validation, explicit force replacement, preflight all known targets and regular-file checks. Return write/close failures. Test inputs below. Port that tight commit to main after the monitor path has moved out.
4. Background codex, mechanical only: copy the two reviewed LLM generator files to main, and the parent-owned common command test/spec to LLM. Destinations must be absent; preserve bytes. Parent independently hashes each source/destination pair before validation.
5. Parent inline: update README/current command references and provide migration instructions. Preserve historical records by marking superseded where appropriate. Verify actual -h outputs and common role flags on both branches.
6. Parent inline: existing moved TUI tests, focused generator tests, full suites/race/build on both branches. Isolated output folders only; no real model tests needed for command relocation. Review diff, commit locally, comment/update issues.

No broad gathering is needed: relevant command sources and references are known. The delegated units are the mechanical relocation of 3 files and the byte-preserving transfer of 4 shared files; design, generator changes and verification stay with the parent.

## Acceptance inputs / expected

- Build each command to a temporary executable and invoke -h with a short process timeout. Monitor lists -log-dir/-alerts-file; generator lists -out/-count/-force with sample-logs default; help never starts monitoring or writes logs.
- Isolated empty target, count3 -> exactly3 supported log files, each3 parseable lines.
- Existing auth.log OR ssh.log OR web.log with marker bytes -> default invocation fails and preserves every existing file; no earlier new output files are created during preflight failure.
- Explicit -force permits replacing only named regular target files. Unrelated marker files remain unchanged. Existing target directory/symlink is rejected before changing other logs.
- Count0/negative -> clear error and no output directory creation.
- Default no -force uses O_EXCL so a target appearing after preflight cannot be truncated.
- Writer failure -> nonzero/error, never a success message; close errors are checked.
- Old main loggen -log-dir -> usage error before any filesystem modification.
- Moved TUI pause/severity/time/journal/report regressions keep passing.
- LLM generator smoke uses a temporary directory and count3, without contacting Ollama.

## Limits

The command migration is an intentional interface change on main. -force explicitly authorizes replacement and is not an all-files transaction; errors are surfaced and generation may leave partial new output. Generation remains random synthetic data and does not guarantee an attack alert for each run. Interactive desktop TUI rendering is separate from headless command and model-update tests.
