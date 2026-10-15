#!/usr/bin/env bash
# The crate's tests against a real Postgres: a throwaway Postgres 17 on its own network, and the stack's dev
# container joined to it with STORAGE_TEST_DATABASE_URL set, running the crate's whole suite, database
# tests included (they skip without it).
#
#   bash tests/db.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
engine="${STACK_ENGINE:-docker}"
net="snout-storage-db-$$"
pg="snout-storage-pg-$$"

"$engine" network create "$net" >/dev/null
cleanup() {
	"$engine" rm -f "$pg" >/dev/null 2>&1 || true
	"$engine" network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
"$engine" run -d --rm --name "$pg" --network "$net" -e POSTGRES_PASSWORD=test postgres:17-alpine >/dev/null
until "$engine" exec "$pg" psql -U postgres -tAc 'select 1' >/dev/null 2>&1; do sleep 0.5; done

# The stack's dev container: two levels up in the monorepo, one in the published repository.
dev="$here/../../scripts/dev.sh"
[ -f "$dev" ] || dev="$here/../scripts/dev.sh"

STACK_DEV_ARGS="--network $net -e STORAGE_TEST_DATABASE_URL=postgres://postgres:test@$pg:5432/postgres" \
	bash "$dev" cargo test -p snout-storage -- --nocapture
