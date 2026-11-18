#!/usr/bin/env bash
# RFC-0037's proofs: runs every Kani harness in src/proofs, one at a time, each under a memory cap and a time limit. A
# harness that runs out of either fails, as a failed proof does.
#
#   scripts/prove.sh [HARNESS...]      default: every harness
#
# Needs Kani (`cargo install --locked kani-verifier && cargo kani setup`). `--ignore-global-asm`: the HAL's trap entry is
# assembly, outside what the proofs cover. `-Z stubbing`: the hardware stubs in src/proofs/stubs.rs.
set -u
cd "$(dirname "$0")/.." || exit 2
MEMORY=${PROVE_MEMORY:-16G}
SECONDS_EACH=${PROVE_SECONDS:-1800}
UNWIND=${PROVE_UNWIND:-9}
if [ $# -eq 0 ]; then
    # Every harness, macro-generated ones included: Kani's own metadata, from a code-generation pass, lists them. Only
    # metadata that pass writes counts: a single-harness run leaves metadata naming only that one.
    marker=$(mktemp)
    sleep 1
    touch src/proofs/mod.rs # so this pass rebuilds, and writes fresh metadata, even with nothing changed
    cargo kani -Z unstable-options --ignore-global-asm -Z stubbing --only-codegen >/dev/null 2>&1 || { echo "the proofs don't build"; exit 2; }
    meta=$(find target/kani -name '*.kani-metadata.json' -newer "$marker" | head -1)
    rm -f "$marker"
    [ -n "$meta" ] || { echo "no Kani metadata from this build"; exit 2; }
    set -- $(python3 -c 'import json,sys; print(" ".join(sorted(h["pretty_name"].split("::")[-1] for h in json.load(open(sys.argv[1]))["proof_harnesses"])))' "$meta")
    expected=$(grep -c '#\[kani::proof\]' src/proofs/*.rs | awk -F: '{s+=$2} END {print s}')
    [ "$#" -ge "$expected" ] || { echo "only $# harnesses listed, fewer than the $expected #[kani::proof] lines"; exit 2; }
    echo "$# harnesses"
fi
failures=0
for h in "$@"; do
    start=$(date +%s)
    # A cap on physical memory (a systemd scope), not `ulimit -v`: SAT solvers reserve far more address space than they use.
    out=$(systemd-run --user --scope -q -p MemoryMax="$MEMORY" -p MemorySwapMax=0 timeout "$SECONDS_EACH" \
        cargo kani -Z unstable-options --ignore-global-asm -Z stubbing --default-unwind "$UNWIND" \
        --harness "proofs::$h" --exact 2>&1)
    took=$(($(date +%s) - start))
    if grep -q 'VERIFICATION:- SUCCESSFUL' <<<"$out"; then
        printf 'proved  %-32s %4ss\n' "$h" "$took"
    else
        why=$(grep -E '^Failed Checks:' <<<"$out" | sed 's/^Failed Checks: //' | paste -sd ';' -)
        [ -z "$why" ] && why=$(grep -m1 -E 'out of memory|std::bad_alloc' <<<"$out" || true)
        [ -z "$why" ] && grep -q 'Runtime Symex' <<<"$out" && ! grep -q 'VERIFICATION' <<<"$out" && why="killed: over $MEMORY, or out of time"

        [ -z "$why" ] && why=$( [ "$took" -ge "$SECONDS_EACH" ] && echo "timed out" || tail -1 <<<"$out")
        printf 'FAILED  %-32s %4ss  %s\n' "$h" "$took" "$why"
        failures=$((failures + 1))
    fi
done
[ "$failures" -eq 0 ] && echo 'all proved' || { echo "$failures failed"; exit 1; }
