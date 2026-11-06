# safer-runner-action-test

Real-runner test suites for [safer-runner-action](https://github.com/portswigger-tim/safer-runner-action).
Every workflow uses `portswigger-tim/safer-runner-action@main`, so the suites validate the
action's development head on real GitHub-hosted runners.

## Workflows

| Workflow | Runs on | What it covers |
|---|---|---|
| `test-ubuntu-latest.yml`, `test-ubuntu-24.04.yml`, `test-ubuntu-26.04.yml` | one runner image each | Calls `suite.yml` for that image: enforce, advisory (sudo kept), analyze, strict privilege layer, crash recovery and container egress. `test-ubuntu-latest.yml` also runs the job-container (F3) checks and a 5x enforce soak. |
| `suite.yml` | reusable | Every scenario job for one OS (`os` input). Set `only` to run a single job. |
| `attack-replay.yml` | `ubuntu-latest` | Replays real supply-chain attacks (tj-actions, Shai-Hulud, curl\|bash stagers, DNS tunnelling, dependency confusion) using fake canary secrets. Every exfil attempt must be blocked. |

All of them run on pushes and PRs to `main`, weekly on a schedule (to catch runner-image drift), and on
manual dispatch. In the per-OS workflows, the dispatch `only` input runs a single job.

## Checks

The `tests/` scripts do the checking. A workflow step calls `tests/checks.sh <section>` or
`tests/containers.sh <section>`, and each result is recorded as PASS, FAIL or INFO. The final
`results` step (`finish` in `tests/lib.sh`) writes the results table to the job summary and
fails the job if any check failed. Evidence (proxy flow logs, DNS log, iptables, journals) is
uploaded as an artifact for 7 days.
