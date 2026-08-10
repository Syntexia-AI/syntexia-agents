# syntexia-agents

Internal security fleet for Claude Code. Phased, gated, never pushes.

Twelve specialist subagents plus one orchestration command run a pre-delivery
security and robustness sweep on a product repository: reconnaissance, secrets,
dependencies, SAST triage, authorization and tenant isolation, API and webhook
hardening, LLM-specific risks, resilience, infrastructure review, then guarded
tests, minimal fixes and evidence-based reports. Two human gates: one before
any fix, one before the report.

## What is enforced vs asked

Some controls hold against a misbehaving model; others are prompt-level requests
that a targeted injection could ignore. Do not conflate them.

- Enforced technically: `permissions.deny` in `.claude/settings.json` (the primary
  barrier against push/merge/PR/destructive commands), the fail-closed
  `block_push.py` PreToolUse hook (defense in depth), `validate_fleet.py` in CI,
  and the two human gates.
- Asked by prompt: each agent's read-only and untrusted-content rules, and the
  output contracts.

The hook parses a command line; it cannot see a push hidden inside a shell script,
an `xargs`-fed git call, or a shell alias. Against a targeted injection the real
protection is `permissions.deny` plus the human gates, not the hook. See
`PLAYBOOK.md` section 8.

## Layout

`agents/` (subagent definitions), `commands/` (the `/security-sweep`
orchestrator), `hooks/` (anti-push guard + settings deny-list),
`scripts/` (fleet validation, findings consolidation, ASVS matrix generation,
recall measurement), `templates/` (report skeletons + findings JSON schema),
`reference/` (OWASP ASVS 5.0 requirements), `fixtures/vulnerable-app/`
(known-vulnerable witness repo with expected findings).

## Install into a product repo

    ./install.sh /path/to/repo

Manifest-based sync: removes files from a prior fleet install, copies the current
version, writes `.claude/FLEET_VERSION` (fleet commit SHA + date) so every report
is traceable to the fleet commit that produced it.

Operating manual: [PLAYBOOK.md](PLAYBOOK.md) (French). Change history:
[CHANGELOG.md](CHANGELOG.md).

Internal use only. Proprietary. Keep this repository private. See LICENSE.
