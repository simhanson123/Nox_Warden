# Retained authority validation measurements

The PR23 follow-up changes existing-database open/current maintenance and
peer-change refresh to consistent read snapshots. Actual initialization and
legacy upgrades remain serialized. Full verification still grows with retained
history; these measurements do not establish a supported production capacity.

## Measured comparison

The baseline is `4cef6acf7e46289b156fcd56ad0ab2f2920fabd6`. Its clean archive
received only the same manual test harness; production source was unchanged.
Both implementations read the same privately generated SQLite fixtures containing
0, 100 or 500 genuinely prepared and cancelled test-authority jobs, their reviewed
plans/native evidence and 21, 1,115 or 5,515 audit rows. No quota rows, triggers
or indexes were fabricated or removed to generate this benchmark.

Measurements used Rust1.99.1 on Linux x86_64, AMD EPYC9V74, a four-core CPU quota
and 32GiB memory. Both default Cargo builds reported `dev profile [unoptimized +
debuginfo]`; no release/profile/debug-symbol override was supplied. Resolved
compiler flags were not separately captured. Other builds/tests were stopped
during the final timing window. Each value below is the median of three samples.

| Retained cancelled jobs | Library open before | Library open after | Normal CLI before | Normal CLI after |
| --- | ---: | ---: | ---: | ---: |
| 0 | 0.031s | 0.036s | Not measured | Not measured |
| 100 | 1.382s | 0.836s | 2.185s | 1.681s |
| 500 | 7.563s | 4.172s | 8.158s | 4.826s |

The first empty-database sample in each process includes independent reference
schema setup: 0.624s before and 0.668s after. The medians above include that sample
and two warm samples. Each normal CLI sample starts a separate process, passes
`{}` to `read-signing-project-quota`, and verifies exit0 and a valid JSON object.
At 500 jobs, observed median time decreases by approximately 44.8% for library
open and 40.8% for the CLI. These are development measurements, not latency SLAs.

The candidate measurements include token-error invalidation but precede the
behavior-preserving `map_err` to `inspect_err` cleanup and the final bounded
writer-acquisition retry refinement. The measured read-only open/CLI paths do
not execute that writer retry, but those later changes were not rebenchmarked.
A candidate tree digest was not captured at timing time; do not describe these
numbers as a benchmark of the final immutable commit. Complete final regression
validation is recorded separately in [reports](../reports/README.md).

The external review's 20,000 primitive-row measurements are not reproduced or
directly comparable to these complete lifecycle fixtures. The first separate
local R4 harness failed compilation and produced no measurements; this successful
normal-lifecycle benchmark was independently written afterward.

## Reproduce with current code

The ignored manual harness is
`crates/fw_authority/src/store/open_validation_benchmarks.rs`. It creates a new
private output directory and refuses to overwrite fixture databases. Fixture
creation itself is expensive and is excluded from each reported open sample.

```sh
source scripts/dev-env.sh
perf_fixtures=$(mktemp -d /tmp/nox-open-fixtures.XXXXXX)
FW_OPEN_BENCH_DIR="$perf_fixtures" \
  cargo test --locked -p fw_authority --lib \
  store::open_validation_benchmarks::retained_open_genuine_cancelled_scaling \
  -- --ignored --exact --nocapture
FW_OPEN_BENCH_DIR="$perf_fixtures" FW_OPEN_BENCH_READ_EXISTING=1 \
  cargo test --locked -p fw_authority --lib \
  store::open_validation_benchmarks::retained_open_genuine_cancelled_scaling \
  -- --ignored --exact --nocapture
cargo build --locked -p fw_authority --bin fw_authority_admin
python3 - "$perf_fixtures" target/debug/fw_authority_admin <<'PY'
import json, sqlite3, statistics, subprocess, sys, time
from pathlib import Path
fixtures, binary = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
for count in (100, 500):
    database = fixtures / f"cancelled-{count}.sqlite3"
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    org, project = connection.execute(
        "SELECT org_id,project_id FROM authority_projects LIMIT 1"
    ).fetchone()
    connection.close()
    samples = []
    for _ in range(3):
        start = time.perf_counter()
        result = subprocess.run(
            [str(binary), "read-signing-project-quota", "--database", str(database),
             "--org-id", org, "--project-id", project],
            input=b"{}", capture_output=True,
        )
        elapsed = time.perf_counter() - start
        assert result.returncode == 0, "fixture CLI failed"
        assert isinstance(json.loads(result.stdout), dict)
        samples.append(elapsed)
    print(count, samples, statistics.median(samples))
PY
```

For a before/after comparison, use separate build directories, the same build
profile and these same fixture files. Add only the manual harness and its
`#[cfg(test)] mod open_validation_benchmarks;` declaration to an isolated baseline
archive. Do not delete active targets or rebuild a test executable while its
subprocess fixtures are running. Keep the original fixture directory for both
versions; do not generate weaker legacy rows for one side.

Deterministic concurrency regressions in `open_validation_tests.rs` check that a
separate writer can commit during existing open, same-version maintenance and
peer-change refresh, while corrupted retained records still refuse. The separate
competing-migration regression passed when run without an overlapping executable
rebuild. This does not establish the cause of Claude's earlier SQLITE_BUSY case.

Read snapshots can retain WAL pages, and continuous external writes can exhaust
admission's three snapshot acquisition attempts and require caller retry. This
limits attempts rather than elapsed time or total history-reading cost. A complete
history check remains necessary after a peer commit; local cache reuse is neither
an external audit anchor nor protection from arbitrary in-process/offline attacks.
