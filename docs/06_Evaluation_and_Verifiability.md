# 06 — Evaluation and Verifiability

This document answers the single hardest question a panel can ask:

> **"How do we know your numbers are real, and not something the model or the team made up?"**

Everything below exists to make the answer airtight.

---

## 1. The core idea: ground truth by execution

Most student machine-learning projects report accuracy on a dataset the team *labelled themselves* — which invites
the fair objection that the labels (and therefore the accuracy) are just the team's assumptions restated. ASCEND
avoids this entirely:

> **Our labels are not opinions. They are the recorded outcome of actually running each attack technique in the
> isolated lab.** A technique either escalated privilege or it did not; a path either executed end-to-end or it did
> not. The verifier records that outcome directly.

This turns "we think this path works" into "we ran this path and it worked," which is not arguable.

---

## 2. The four things we measure (and what we compare each against)

| What | Metric | Compared against | Why this metric |
|---|---|---|---|
| **Path-finder** | Precision and recall of proposed paths vs. paths that actually execute | A timing-window-only correlation heuristic | Precision tells us how often a proposed path is real; recall tells us how many real paths we find |
| **Exploitability scorer** | Accuracy, precision, recall, **macro-F1** on held-out hosts | (1) majority-class baseline, (2) "CVSS ≥ 7" baseline | Classes are imbalanced, so macro-F1 (not plain accuracy) is the honest headline |
| **Remediation** | Does the recommended fix set rank truly critical paths above non-critical ones; how many paths each fix removes | Raw CVSS-ordering of fixes | Shows chokepoint analysis beats "just fix the highest-CVSS thing" |
| **Pipeline** | p50 / p95 / p99 latency; sustained event rate | A stated target (SLO) of p95 < 5 seconds | Honest performance reporting on real hardware |

**Every number reported comes from the held-out test set, evaluated once.** Tuning against the test set and then
reporting it is the most common way student projects accidentally overstate results; we evaluate on the test set a
single time, after all tuning is done on the validation set.

---

## 3. How we prevent data leakage (split by host, and by scenario)

- **Split by host.** Every finding from a given machine goes entirely into either the training set or the test set,
  never both. This means the test always measures generalisation to machines the model has never seen. (Splitting
  individual findings randomly would let the model see part of a machine's data in training and be quizzed on the
  rest — impressive but meaningless.)
- **Hold out whole scenario variants.** Better still, we hold out entire *attack-scenario variants*, so the test
  measures generalisation to chains the model has never seen, not memorisation of ones it has.
- **One-time test evaluation.** The test set is opened once, at the end.

---

## 4. Why there is a genuine prediction problem (not a replay of our script)

If every lab run followed the same scripted chain, a model "discovering" that chain would just be reading our
script back. So our scenario library **branches** — the next step is genuinely uncertain given the current one:

| Scenario class | Path | Purpose |
|---|---|---|
| Full chain | foothold → escalate → move → reach crown jewel | The positive case |
| Early stop | foothold, then nothing further | Not every intrusion continues |
| Local objective | escalate and act on the same host, no movement | Escalation does not always imply movement |
| Failed escalation | attempt an exploit that fails, then stop | Attacks fail; the model must tolerate it |
| Benign look-alike | a legitimate admin using SSH between hosts | SSH is not always an attack (guards against false positives) |
| Background only | ordinary application and user traffic | The negative class |

Without the last three rows in particular, the model would have no way to learn **when not to raise a path**, and its
precision on benign activity would be meaningless.

---

## 5. Reproducibility (anyone can re-run and get the same numbers)

- The lab is defined as **versioned container images and configuration** — the same inputs every time.
- The scope is a **versioned `scope.yaml`**; changing scope is a reviewed change to that one file.
- Data-generation and training use **fixed random seeds**, so a re-run reproduces the dataset and the metrics.
- Result tables and figures are produced by scripts in `eval/`, not hand-edited, so the reported numbers are exactly
  what the code computed.

If a panel member says "run it again," the numbers come out the same. That is the practical test of "not
hallucinated."

---

## 6. The clinching demonstration: before/after remediation

The strongest evidence is not a metric table — it is a **demonstrated cause and effect**:

1. ASCEND enumerates and verifies the attack paths.
2. It recommends a small chokepoint fix set.
3. We **apply** the top fix in the lab.
4. We **re-run** enumeration and verification.
5. The paths that depended on that fix are **gone**.

This is a controlled experiment with a manipulation and an observed effect. It cannot be produced by a model
hallucinating; it either happens on the live lab or it does not.

---

## 7. Threats to validity (state these before the panel does)

Good research names its own limitations. Ours:

- **Lab realism.** Our lab is smaller and cleaner than a real enterprise network. We mitigate by keeping background
  noise, failed attempts and benign look-alikes, but we state plainly that lab-to-production transfer is not proven.
- **Scope narrowness.** Results hold for the seven in-scope techniques on Linux; we do not claim they generalise to
  other techniques or to Windows.
- **Execution as labelling.** Continuously executing attacks is not how production runs; in production, verification
  would be periodic and authorised. Our use of execution is for trustworthy labels and remediation proof.
- **Centralised prototype.** A single collector/analysis service is a single point of failure and does not scale
  horizontally; scaling is stated as future work, with our measured event rate reported rather than an inflated
  claim.

Naming these *raises* credibility — it shows the results are understood, not oversold.
