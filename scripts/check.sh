#!/usr/bin/env bash
# The security checks X13 asks for, run LOCALLY rather than in CI.
#
# X13 first said "in CI". The GitHub Actions budget is why .github/workflows only builds
# releases (security-scan.yml lost its triggers on 2026-07-17 for the same reason), so these
# are a script, and the fast ones also run from scripts/hooks/pre-push on any push that
# touches packages/stack/. Fuzzing is scripts/fuzz.sh, run per step for its time budget.
#
#   bash scripts/check.sh          cargo-deny (licences, bans, sources, advisories),
#                                  cargo-audit, and gitleaks over this directory
#   bash scripts/check.sh --fast   the same without cargo-audit (the pre-push hook's set).
#                                  cargo-deny's advisories check reads the same RustSec
#                                  database, so --fast still refuses a known vulnerability
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fast=""
[ "${1:-}" = "--fast" ] && fast=1

exec bash "$here/dev.sh" bash -c '
	set -euo pipefail
	echo "== cargo deny"
	cargo deny --locked check licenses bans sources advisories
	if [ -z "'"$fast"'" ]; then
		echo "== cargo audit"
		cargo audit --db /cache/advisory/rustsec --deny warnings
	fi
	echo "== gitleaks"
	# --no-git: the directory as it will be mirrored, which is what a reader of the public
	# repository sees. The whole repository history is the repo-wide scan, scripts elsewhere.
	gitleaks detect --no-git --source . --redact --exit-code 1 --no-banner
'
