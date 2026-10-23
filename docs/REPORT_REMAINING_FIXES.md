# Phase I report: remaining fixes

Checked against the Google Doc (`1Fw25eQjWd4HEQLkGUGy53Mrp93oiFoxzWZ41EXIWWrU`,
tab 1) as read on 2026-10-24. These are the places that still contradict the
run of 2026-10-22. Everything else from the earlier fills
(`REPORT_PLACEHOLDER_FILLS.md`, renamed to this file) is already in the doc.

Source of every number here:

| Number | Value | Source |
|---|---|---|
| Automated tests | 52 (8 signal + 11 scope + 33 pipeline), all pass with the lab up | `pytest tests verifier/tests` |
| Enumeration latency p50 / p95 / p99 | 0.033 / 0.042 / 0.044 ms | `eval/analysis.json` (timing) |
| Precision | 1 of 2 routes (0.5) | `eval/verify_run.json`, run `run-f4cb5dd5` |

---

## 1. Abstract

Find: `the codebase carries 48 automated checks`
Replace: `all 52 automated checks pass with the laboratory running`

## 2. Section 5.2 (test suite intro)

Find: `The suite contains 48 automated tests in three files`
Replace: `The suite contains 52 automated tests in three files`

## 3. Table 5.1

| Row | Old | New |
|---|---|---|
| tests/test_pipeline.py, Tests | 29 | **33** |
| Total, Tests | 48 | **52** |

## 4. Section 5.3 (intro sentence)

Find: `with the laboratory not running.`
Replace: `with the laboratory running.`

## 5. Table 5.2

| Row | Old Result | New Result |
|---|---|---|
| TC14 | Fail (Docker not running) | **Pass** |
| TC15 | Skipped (laboratory down) | **Pass** |

## 6. Section 6.2 (performance)

Find: `The 95th-percentile latency of 0.031 ms`
Replace: `The 95th-percentile latency of 0.042 ms`

## 7. Table 6.4

| Row | Old | New |
|---|---|---|
| Enumeration latency p50 / p95 / p99 (50 runs), value | 0.025 / 0.031 / 0.198 ms | **0.033 / 0.042 / 0.044 ms** |
| Precision (execution-verified routes), value | `of 2 (0.5); …` (the leading **1** is missing) | **1 of 2 (0.5); route 2 partial, DirtyPipe not executable** |
| Precision, source | analysis.json, README | **verify_run.json (run-f4cb5dd5)** |
| Automated tests, label | Automated tests (offline) | **Automated tests (laboratory up)** |
| Automated tests, value | 44 pass, 1 fail, 3 skip of 48 | **52 of 52 pass** |

## 8. Section 6.3 (formatting only)

The bold run takes in the first letter of the next sentence:
`**Verification results are stored with their run. E**very per-route…`
Un-bold the `E` of "Every" so that only the lead sentence is bold.

## 9. Section 7.2, contribution 5

Find: `together with a 48-test suite`
Replace: `together with a 52-test suite`

## 10. Section 2, Ben Fredj and Cheikhrouhou [30]

`…aimed at anticipating multi-step attacks in real time; their code is public.`

Still unverified: the Springer page is paywalled, and no repository turned up in
a search. Check the paper's *Code availability* statement. If it does not link a
repository, replace the whole clause with:

`…aimed at anticipating multi-step attacks in real time.`

---

## Already in the doc (no action)

- Abstract: the partial-route wording that replaced `[RE-RUN VERIFIER WITH LAB UP]`
- Section 3.2: development machine (the doc says 48 GB of RAM; `free` reports 46 GiB usable, which is consistent with 48 GB installed)
- Section 5.3: "Summary of the run" paragraph (52 tests)
- Section 6.1.3: per-route verification and repeated technique runs
- Section 6.3: traceability paragraph
- Section 7.3: batch-staging limitation bullet
- Reference [30]: `no. 4` added
- Reference [31]: correct as written
- Gao et al.: no longer cited and no longer in the reference list
