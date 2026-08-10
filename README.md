# syntexia-agents

Internal security fleet for Claude Code. Phased, gated, never pushes.

Twelve specialist subagents plus one orchestration command run a pre-delivery
security and robustness sweep on a product repository: reconnaissance, secrets,
dependencies, SAST triage, authorization and tenant isolation, API and webhook
hardening, LLM-specific risks, resilience, infrastructure review, then guarded
tests, minimal fixes and evidence-based reports. Two human gates: one before
any fix, one before the report. All git pushes, merges and PRs stay human.

Layout: `agents/` (subagent definitions), `commands/` (the `/security-sweep`
orchestrator), `hooks/` (anti-push guard), `scripts/` (fleet validation),
`templates/` (report skeletons), `reference/` (OWASP ASVS 5.0 requirements).

Install into a product repo: `./install.sh /path/to/repo`

Operating manual: [PLAYBOOK.md](PLAYBOOK.md) (French).

Internal use only. Proprietary.
