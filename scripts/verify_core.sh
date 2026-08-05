#!/usr/bin/env bash
set -euo pipefail

CC="${CC:-gcc}"
STRICT_CFLAGS="-std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude"

# GCC reports deliberate, explicitly terminated display-label truncation as
# stringop-truncation. Keep the warning visible without turning that single
# compiler-specific heuristic into a build blocker.
if [[ "$(basename "$CC")" == gcc* ]]; then
    STRICT_CFLAGS+=" -Wno-error=stringop-truncation"
fi

printf '== Changed-line validation ==\n'
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    git diff --check "origin/${GITHUB_BASE_REF}...HEAD"
elif git rev-parse HEAD^ >/dev/null 2>&1; then
    git diff --check HEAD^...HEAD
else
    git diff --check
fi

printf '\n== Repository hygiene ==\n'
python3 -m unittest tests/test_repo_hygiene.py -v

printf '\n== Strict build with %s ==\n' "$CC"
make clean
make CC="$CC" CFLAGS="$STRICT_CFLAGS"

printf '\n== Smoke checks ==\n'
make CC="$CC" CFLAGS="$STRICT_CFLAGS" check

printf '\n== Unit and contract tests ==\n'
make CC="$CC" CFLAGS="$STRICT_CFLAGS" test

printf '\n== Deterministic CLI smoke ==\n'
pulse_log="$(mktemp)"
core_log="$(mktemp)"
trap 'rm -f "$pulse_log" "$core_log"' EXIT

./build/pulse_kernel --dry-run --limit=2 >"$pulse_log"
./build/liminal_core --substrate --limit=2 --trace >"$core_log"

test -s "$pulse_log"
test -s "$core_log"

printf '\nCore verification passed.\n'
