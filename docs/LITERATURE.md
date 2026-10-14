# Literature Review

The pyroXD detection engine is a synthesis of established, peer-reviewed methods
for streaming anomaly detection, chosen so that every component is explainable
and citable rather than a black box. This document records what each method
contributes and why it was selected.

## Streaming one-class anomaly detection

- **Tan, S.C., Ting, K.M., Liu, T.F. (2011). "Fast Anomaly Detection for
  Streaming Data." *IJCAI 2011*, 1511–1516.** The flagship. Half-Space Trees
  give one-class anomaly detection in *constant time and memory* with a built-in
  drift-adaptation mechanism (reference/latest mass windows). This directly
  matches the real-time constraint and is implemented from the paper in
  `detect/halfspace_trees.py`.
- **Liu, F.T., Ting, K.M., Zhou, Z.-H. (2008). "Isolation Forest." *ICDM
  2008*.** The isolation principle underpinning HST — anomalies are *few and
  different*, hence easier to isolate with random partitions. HST is the
  streaming successor; iForest is its batch ancestor and motivates the random
  half-space partitioning.

## Distribution-based (collective) anomaly detection

- **Lakhina, A., Crovella, M., Diot, C. (2005). "Mining Anomalies Using Traffic
  Feature Distributions." *ACM SIGCOMM 2005*.** Establishes that the *entropy*
  of traffic-feature distributions (ports, addresses) is a powerful, compact
  signal for network anomalies — scans and floods move entropy sharply even when
  individual flows look normal. Basis for `detect/entropy.py`.
- **Nychis, G., Sekar, V., Andersen, D.G., Kim, H., Zhang, H. (2008). "An
  Empirical Evaluation of Entropy-based Traffic Anomaly Detection." *IMC
  2008*.** Tempers the above: entropy signals on correlated features can be
  redundant. Informs our choice of two *complementary* entropy views
  (destination port vs destination IP) rather than many correlated ones.

## Statistical process control

- **Roberts, S.W. (1959). "Control Chart Tests Based on Geometric Moving
  Averages." *Technometrics* 1(3), 239–250.** The EWMA control chart, still a
  workhorse for network baselining. Basis for `detect/ewma.py`, used here for
  volumetric spike detection.
- **Welford, B.P. (1962). "Note on a Method for Calculating Corrected Sums of
  Squares and Products." *Technometrics* 4(3).** The numerically stable online
  mean/variance recurrence used throughout our calibration and EWMA code.

## Score calibration and fusion

- **Platt, J. (1999). "Probabilistic Outputs for Support Vector Machines."**
  Motivates mapping an unbounded detector score to a probability via a logistic
  of a standardised value — adapted here into the one-sided, streaming
  `StreamingNormalizer`.
- **Noisy-OR fusion** (Pearl, J. (1988). *Probabilistic Reasoning in Intelligent
  Systems*). The combination rule used to fuse independent detector opinions:
  anomalous if any credible detector is confident. Chosen over averaging so a
  single-signal attack is not washed out.

## Evaluation methodology

- **Window-bleed / event attribution.** Measuring streaming collective detectors
  per-flow over-counts the transient immediately after an event. We report
  steady-state false-positive rate separately, consistent with incident-grouping
  practice in operational IDS evaluation.
- **Planned external validation.** Before any operational performance claim, the
  engine will be validated on public labelled flow corpora (e.g. the CIC-IDS /
  NSL-KDD lineage of intrusion-detection datasets). This is tracked in
  `ROADMAP.md`; current numbers are explicitly on synthetic lab traffic.

## How the pieces fit

| Threat shape | Primary method | Citation |
|---|---|---|
| Multivariate outlier (odd combination of features) | Half-Space Trees | Tan 2011 |
| Univariate volumetric spike (exfiltration) | EWMA control chart | Roberts 1959 |
| Collective scan/flood (distribution shift) | Streaming entropy | Lakhina 2005 |
| Cross-signal decision | One-sided calibration + noisy-OR | Platt 1999; Pearl 1988 |
