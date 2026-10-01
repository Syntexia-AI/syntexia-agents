# syntexia-agents

Internal security fleet for Claude Code. Phased, gated, never pushes.

Twelve specialist subagents plus one orchestration command run a pre-delivery
security and robustness sweep on a product repository: reconnaissance, secrets,
dependencies, SAST triage, authorization and tenant isolation, API and webhook
hardening, LLM-specific risks, resilience, infrastructure review, then guarded
tests, minimal fixes and evidence-based reports. Two human gates: one before
any fix, one before the report.

## Quick start

    ./scripts/prepare_sweep_clone.sh <product repo path or URL> /tmp/sweep-<name>
    cd /tmp/sweep-<name> && claude          # or: claude --settings .claude/settings.sandbox.json
    /security-sweep full

The disposable clone has no untracked files (no `.env`), no remote and no git
credential helper; the fleet is installed in it and `.claude/` is excluded from
its commits. Bring the reviewed branch back with `git fetch <clone> <branch>`
from your usual clone. Details: [PLAYBOOK.md](PLAYBOOK.md) (French).

One sweep at a time per machine: every sweep works in `/tmp/sweep`, which must be
absent or empty when a sweep starts (Phase 0 stops otherwise) and is deleted
after the report. A run marker binds the consolidation to the current sweep, so
agent files left by an earlier sweep, possibly of another client, are never
merged into this one.

## What is enforced vs asked

Some controls hold against a misbehaving model; others are prompt-level requests
that a targeted injection could ignore. Do not conflate them.

Enforced technically, strongest first:
- Disposable clone (`scripts/prepare_sweep_clone.sh`): nothing to push to, no
  credentials, no live secrets on disk.
- Session environment (`env` in `.claude/settings.json`): git global and system
  config ignored (no aliases, credential helpers or URL rewrites from the host),
  SSH transport disabled.
- Optional OS sandbox (`.claude/settings.sandbox.json`): network limited to the
  vulnerability databases, host credentials unreadable, no unsandboxed escape,
  hard failure when unavailable.
- `permissions.deny`: harness-level refusal, active even in bypass mode (which the
  fleet settings disable). Bash patterns are string matches, so `Bash(git push *)`
  alone would not cover `git -C . push`: the template adds mid-pattern wildcards
  and bans whole tools that a sweep never needs (`gh`, `curl`, `ssh`, `aws`,
  `docker`, `sudo`, package installs).
- PreToolUse hook `hooks/block_push.py` (Bash, Read, Grep, Edit, Write): a
  fail-closed parser that understands wrappers, nested shells, heredocs,
  substitutions, inline interpreter code and shell scripts on disk; git is limited
  to an allowlist; secrets, the environment, `.claude/`, `.git/` and writes
  outside the project and `/tmp/sweep` are protected. Covered by 465 attack and
  benign cases in `scripts/test_hook.py`, including every bypass found by three
  rounds of independent adversarial review.
- CI: fleet validation, hook matrix, installer integration tests, script
  self-tests, hygiene, ShellCheck.
- The two human gates.

Asked by prompt: each agent's read-only, output-hygiene and refusal rules, and the
output contracts.

Known limits: the hook cannot see a renamed copy of a binary or code that an
allowed program loads by itself (a test suite, a build target not named like a
release). Against a targeted injection the protection is the combination above,
not the hook alone. See `PLAYBOOK.md` section 8.

## Layout

`agents/` (subagent definitions), `commands/` (the `/security-sweep`
orchestrator), `hooks/` (guard hook, settings template, sandbox profile),
`scripts/` (sweep runtime: preflight, redacted secret scan, consolidation, ASVS
matrix; fleet tooling: clone preparation, settings check and merge, validation,
tests, hygiene, recall measurement), `templates/` (report skeletons + findings
JSON schema), `reference/` (OWASP ASVS 5.0 requirements),
`fixtures/vulnerable-app/` (known-vulnerable witness repo with expected
findings).

## Install into an existing clean repo

    ./install.sh [--merge-settings] /path/to/repo

Refuses a live checkout (untracked secret files), symlinked install paths and an
incomplete existing `settings.json` (unless `--merge-settings`). Manifest-based
sync, validated paths only, and `.claude/FLEET_VERSION` (fleet commit, uncommitted
changes flag, date) so every report is traceable to the fleet commit that
produced it.

Change history: [CHANGELOG.md](CHANGELOG.md).

Internal use only. Proprietary. Keep this repository private. See LICENSE.
