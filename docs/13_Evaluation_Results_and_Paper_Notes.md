# 13 — Evaluation Results, Real-World ML Benchmark & Paper Notes

> **Status:** Authoritative, script-grounded research & evaluation record for the
> Phase II IEEE conference paper and final project report.
> Reproducible commands:
> - Real-world CVE ML pipeline: `python3 scorer/fetch_real_cve_dataset.py && python3 scorer/train_real_cve_model.py` → `eval/real_cve_benchmark.json`
> - Multi-variant chokepoint & scalability harness: `python3 eval/benchmark.py` → `eval/benchmark_summary.json`
> - Live Docker variant canary runner (on Docker host): `python3 eval/run_live_variants.py --count 40 --seed 1337`

---

## 1. Real-World ML Exploitability Model (Hardcore IEEE Evaluation)

### 1.1 Dataset & Zero-Leakage Temporal Split
MITRE ATT&CK is a taxonomy (~200 techniques), not a labelled dataset — it is used here properly as **feature enrichment** (`CVE → CWE → CAPEC → ATT&CK`), never as synthetic training rows.

- **Real public data sources** (`scorer/data/real_linux_cves.jsonl.gz`, **9,887 unique real CVEs**, 2018–2026):
  1. **NVD CVE API v2.0** (`services.nvd.nist.gov`) — disclosure-time CVSS v3.1 vector sub-metrics (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`), CWE IDs, and English vulnerability descriptions.
  2. **Exploit-DB** (`files_exploits.csv`, 25,095 unique CVEs with public working exploits) — ground-truth positive label (`y = 1`).
  3. **CISA KEV** (via NVD `hasKev`, 1,790 government-confirmed actively exploited CVEs) — ground-truth positive label (`y = 1`).
  4. **FIRST EPSS API** (`api.first.org/data/v1/epss`) — fetched **strictly as an external live industry ML benchmark comparator** (100% coverage on 2024 test cohort; **never** used as a training feature).
- **Strict temporal split** (following Iannone et al., *ACM TOSEM* 2024; *arXiv:2606.19076*, Jun 2026):
  - **Train (`2018–2022`)**: `5,559` real CVEs (`778` exploited, `14.0%`). TF-IDF vocabulary, scalers, and SVD are fit **strictly on train**.
  - **Validation & Calibration (`2023`)**: `946` real CVEs (`169` exploited, `17.9%`). Used exclusively for Isotonic probability calibration and Macro-F1 threshold selection.
  - **Primary Held-Out Test (`2024`)**: `2,466` real CVEs (`162` exploited, `6.6%` realistic imbalanced prevalence, **100% live EPSS coverage**). Evaluated once with 400-resample 95% bootstrap confidence intervals.
  - **Prospective Cohort Check (`2025–2026`)**: `916` real CVEs (`427` exploited, KEV-enriched — reported separately).

### 1.2 Table A — Real-World CVE Exploitability Results (`2024` Held-Out Test, `N = 2,466`)

| Model / Baseline | Feature Tier | ROC-AUC | PR-AUC | Macro-F1 | Recall@100 | Recall@250 | Brier | ECE |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Majority-Class Baseline | none | 0.5000 | 0.0657 | 0.4830 | 0.1049 | 0.1605 | 0.0669 | 0.0743 |
| CVSS Base ≥ 7.0 Baseline | `cvss_scalar` | 0.7029 | 0.1103 | 0.4551 | 0.1420 | 0.1790 | 0.4319 | 0.4319 |
| CVSS Base Continuous | `cvss_scalar` | 0.7989 | 0.2814 | 0.4551 | 0.2160 | 0.5062 | 0.4206 | 0.6005 |
| Calibrated LR (Tier 1) | `cvss_submetrics` | 0.9013 | 0.4463 | 0.7527 | 0.3086 | 0.6173 | 0.0480 | 0.0405 |
| Calibrated LR (Tier 1+2) | `+CWE/ATT&CK ontology` | 0.9598 | 0.7712 | 0.8950 | 0.5679 | 0.8642 | 0.0217 | 0.0112 |
| Calibrated LR (Full Multimodal) | `+TF-IDF NLP` | 0.9610 | 0.8705 | 0.9450 | 0.5864 | 0.9136 | 0.0129 | 0.0217 |
| Calibrated Random Forest | `Full + SVD` | 0.9346 | 0.8520 | 0.9292 | 0.5926 | 0.8827 | 0.0182 | 0.0409 |
| Calibrated HistGBDT | `Full + SVD` | 0.9327 | 0.8528 | 0.9369 | 0.5926 | 0.8765 | 0.0225 | 0.0543 |
| **ASCEND Calibrated Multimodal Ensemble** | **LR + HistGBDT + RF** | **0.9480** | **0.8860** | **0.9508** | **0.5926** | **0.9136** | **0.0142** | **0.0395** |
| *FIRST EPSS (Live External Industry ML)* | *Live threat intel* | *0.9947* | *0.9427* | *0.9069* | *0.5926* | *0.9630* | *0.0260* | *0.0268* |

**Key scientific findings for the paper & viva:**
1. **3.15× PR-AUC over CVSS Continuous (`0.8860` vs. `0.2814`) and 8.03× over CVSS ≥ 7.0 (`0.1103`)** on unseen 2024 CVEs, using **strictly disclosure-time metadata**.
2. **Every modality earns its place in the ablation**: disaggregating CVSS v3.1 sub-metrics lifts PR-AUC `0.281 → 0.446`; adding CWE/MITRE ATT&CK ontology lifts it `0.446 → 0.771`; adding NVD description TF-IDF NLP + ensemble calibration lifts it `0.771 → 0.886` (`Macro-F1 = 0.9508`).
3. **Competitive with live FIRST EPSS without live threat-intel feeds**: Matches FIRST EPSS on `Recall@100` (`0.5926`), achieves lower Brier error (`0.0142` vs. `0.0260`), and generalizes cleanly to the prospective `2025–2026` cohort (`ROC-AUC = 0.9109`, `PR-AUC = 0.9262`, `Brier = 0.1069` vs. CVSS Continuous `PR-AUC = 0.5917`, `Brier = 0.3497`).
4. **Anchor CVE audit**: On ASCEND's two anchor CVEs, the disclosure-time model scores **PwnKit (`CVE-2021-4034`)** at `0.4310` (live EPSS `0.9492`, KEV=True, EDB=True) and **DirtyPipe (`CVE-2022-0847`)** at `0.4046` (live EPSS `0.9280`, KEV=True, EDB=True) — both well above the validation-tuned positive threshold and the `6.6%` base rate.

---

## 2. Chokepoint Remediation & Scalability Benchmarks (`eval/benchmark.py`, seed `1337`, `N = 40` variants)

### Table B — Chokepoint Remediation vs. Exact Optimal, CVSS-First & Random Order
Evaluated across `36` attackable variants (`4` hardened variants yielded `0` false alarms; `41` collector decoys declined, `0.0%` decoy FP rate):

| Remediation Strategy | Mean Fixes to Full Cover | Mean Cost to Full Cover | Cost Reduction vs. Baseline |
|---|---:|---:|---:|
| **ASCEND Greedy Weighted Set-Cover** | **1.00** | **1.00** | **100.0% optimal** vs. Exact Min-Cost Cover |
| Random Fix Order (15 trials/variant) | 2.26 | 4.69 | ASCEND saves **78.68%** cost |
| CVSS-First (Scanner Severity Order) | 3.14 | 7.11 | ASCEND saves **85.94%** cost |

### Table C — Enumeration Scalability (4 → 64 Hosts vs. 5,000 ms SLO)

| Hosts | p50 (ms) | p95 (ms) | p99 (ms) | Meets 5 s SLO |
|---:|---:|---:|---:|---|
| 4 | 0.098 | 0.203 | 0.214 | Yes |
| 8 | 0.119 | 0.129 | 0.136 | Yes |
| 16 | 0.153 | 0.229 | 0.258 | Yes |
| 32 | 0.198 | 0.520 | 0.549 | Yes |
| 64 | 0.159 | 0.336 | 0.354 | Yes |

---

## 3. End-to-End Architectural Refinements (Observation → Response)

| # | Observation (Problem Found) | Engineering Response |
|---|---|---|
| 1 | **Single-lab ML collapse**: Legacy `outcomes.jsonl` had `positive_rate = 1.0` after cleaning, yielding `0.0` weights. | Added a strict two-class honesty gate in `scorer/model.py` AND built a real-world multimodal CVE exploitability model trained on **9,887 real NVD + Exploit-DB + CISA KEV CVEs** (`scorer/train_real_cve_model.py`). |
| 2 | **Circular benign check**: Stripping vectors in memory proves nothing. | Replaced with `generator/blueprints/hardened_baseline.yaml` carrying real decoy rules examined and declined by derivation rules. |
| 3 | **Multi-hop credential staging gap**: Lateral SSH verification failed if a pivot host lacked a local copy of the stolen key. | Added cross-host credential staging in `verifier/adapters/lateral_ssh.py` and `service/main.py`. |
| 4 | **In-memory vs. live-lab Apply Fix**: In-memory graph edits fit read-only Assessment mode, not Lab-mode proof. | Split `POST /api/remediation/apply` into `mode="what_if"` (Assessment) and `mode="live_lab"` (`chokepoint/remediate.py` executes real Linux hardening commands in the container). |
| 5 | **Stale Sentinel docs & unused fixtures**: Old Sentinel PDF/DOCX and 4 mock fixture JSONs cluttered the repo. | Removed `docs/legacy/`, `docs/PLAN_RECONCILIATION_ASCEND_vs_Sentinel.md`, and 4 unused mock fixtures. |

---

## 4. Data-Driven Insights for Improving the Live Demo & Real Privilege Escalation

Training on 9,887 real CVEs exposed **two concrete ways to make your live demo dramatically stronger**:

1. **The "2024 Linux Kernel CNA Scanner-Noise" Demo Story (Huge Viva Impact)**:
   - Our real NVD pull showed that in 2024, the Linux Kernel CNA published **2,249 kernel CVEs**, of which only **0.1% (3 CVEs)** had public exploits or KEV activity — yet vulnerability scanners assign many of them CVSS 7.0–7.8 and drown Linux admins in alerts.
   - In your demo, show **Assessment Mode (Trivy import)** ingesting a noisy list of High-CVSS Linux kernel CVEs alongside 1 reachable misconfiguration/CVE chain: ASCEND's multimodal CVE scorer drops the unexploited kernel noise while the graph enumerator + chokepoint engine surfaces the 1 cheap fix (`chmod 600` on the reused SSH key) that breaks every real route.
2. **Use Userspace `PwnKit` (`CVE-2021-4034`) for Live Container CVE Execution (Not Only DirtyPipe)**:
   - DirtyPipe (`CVE-2022-0847`) is a **kernel** bug, so in Docker it must always report `not_executable` (requiring VMs to run live).
   - **PwnKit (`CVE-2021-4034`)** is a **userspace SUID (`pkexec`)** vulnerability (CVSS `7.8`, live EPSS `0.949`, ASCEND disclosure-time probability `0.431`) — already in your `scope.yaml` and `knowledge_graph/pack.json`. Because `pkexec` lives in userspace inside the container filesystem, a vulnerable `policykit-1` package in a throwaway container lets you demonstrate **real, live `T1068` CVE execution inside Docker** alongside DirtyPipe's honest `not_executable` kernel boundary!

---

## 5. Threats to Validity & Verified ≥2024 References for the Paper

- **Threats to Validity**:
  1. **Disclosure-time vs. live threat intel**: Our model intentionally excludes EPSS and Exploit-DB reference tags to remain leakage-free at disclosure time; live EPSS naturally achieves higher ROC-AUC (`0.9947` vs. `0.9480`) because it incorporates post-disclosure active scanning/IDS telemetry.
  2. **2025–2026 KEV enrichment**: The `2025–2026` prospective cohort is KEV-enriched by sampling, so the `2024` cohort (`N = 2,466`, `6.6%` prevalence) is the primary unbiased benchmark.
  3. **Offline variant outcomes vs. live Docker runs**: Run `python3 eval/run_live_variants.py --count 40 --seed 1337 --output eval/variant_outcomes.jsonl` on a Docker host to replace offline catalogue ground-truth labels with live canary-verified runs.
- **Verified ≥2024 References to Add (Lane 5)**:
  - **Iannone et al. (ACM TOSEM, 2024)** — *Early and Realistic Exploitability Prediction of Just-Disclosed Software Vulnerabilities* (anti-leakage benchmark over NVD + Exploit-DB).
  - **François, Arduin & Merad (J. Cybersecur. Privacy 5(2):15, Apr 2025)** — *Physics-Informed Graph Neural Networks for Attack Path Prediction* (`doi:10.3390/jcp5020015`).
  - **Zhou et al. (arXiv:2411.10279, Nov 2024)** — *LMDetect: Lateral Movement Detection via Time-aware Subgraph Classification*.
  - **Jiang et al. (arXiv:2502.11070, Feb 2025)** — *A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges*.
  - **arXiv:2506.01220 (Jul 2025)** — *An Integrated Framework for Efficient Cybersecurity Risk Prioritization* (EPSS uncertainty vs. CVSS).
  - **Shen et al. (arXiv:2509.17832, Sep 2025)** — *AEAS: Actionable Exploit Assessment System* (CVSS → EPSS → AEAS → executed ASCEND ladder).
  - **arXiv:2606.19076 (Jun 2026)** — *Compute-Budgeted Exploitability Evidence Graphs for Prospective Vulnerability Prioritization* (temporal leakage & auditable evidence).
