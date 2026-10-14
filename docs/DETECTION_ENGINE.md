# The pyroXD Detection Engine

This document explains, in full, how the real-time anomaly/intrusion detection
engine works — the maths, the data flow, and the engineering choices. It is
written so a reader can both *use* the engine correctly and *reproduce* its
design decisions.

## 1. The streaming problem

Real-time intrusion detection is an **online, unsupervised, non-stationary**
problem:

- **Online** — flows arrive one at a time; we must score each immediately and
  keep memory bounded. No batch retraining on the whole dataset.
- **Unsupervised** — we cannot assume labelled attacks in production. The
  engine learns the shape of *normal* and flags departures from it.
- **Non-stationary** — normal traffic drifts (day/night, deployments). A static
  model trained once becomes wrong; the engine must adapt.

Every component below is chosen to satisfy these three constraints.

## 2. Data model and features

A [`FlowRecord`](../src/pyroxd/core/flow.py) is a vendor-neutral flow summary
modelled on the fields common to NetFlow v9 and IPFIX (RFC 7011/7012). Each
flow is projected onto a fixed, 10-dimensional numeric feature vector:

| Feature | Meaning | Catches |
|---|---|---|
| `log_bytes`, `log_packets`, `log_duration_ms` | Log-compressed volume | exfiltration, elephant flows |
| `log_bytes_per_packet` | Mean payload size | traffic-type anomalies |
| `log_packets_per_sec` | Throughput | floods, scans |
| `dst_port_rank` | How unusual the destination port is (0 for well-known) | scans to odd ports |
| `is_tcp`, `is_udp`, `is_icmp` | Protocol one-hots | protocol anomalies |
| `syn_ratio` | Fraction of SYN-only packets | half-open scans, SYN floods |

Heavy-tailed counts are log-compressed so one elephant flow cannot dominate the
scale and so deviation statistics stay meaningful. All values are finite by
construction.

## 3. The four detectors

The engine runs four complementary online detectors. They are complementary by
design: each is strong exactly where the others are weak.

### 3.1 Half-Space Trees (flagship) — multivariate isolation

`pyroxd.detect.halfspace_trees.HalfSpaceTrees`, from **Tan, Ting & Liu, "Fast
Anomaly Detection for Streaming Data", IJCAI 2011**.

- An ensemble of random binary trees is built **once**. Each internal node
  splits a random dimension at the midpoint of that node's range, over a
  randomised "work space" that is guaranteed to contain the unit hypercube
  (the paper's `s ± 2·max(s, 1−s)` construction).
- Only per-node **mass counters** change as data streams in — the structure is
  frozen — which is what gives **O(trees · depth)** updates and **constant
  memory** (verified by `test_hst_constant_memory`).
- Two interleaved windows of size ψ: a frozen **reference** profile used for
  scoring and a **latest** profile being filled. Every ψ points the latest
  profile replaces the reference. This is how HST adapts to drift without
  retraining.
- A point's mass along its root-to-leaf path is high in dense (normal) regions;
  we invert and log-compress it so **isolated points score high**.

HST requires inputs in `[0, 1]^d`, so the engine puts a streaming min-max
scaler (`_StreamingMinMax`) in front of it. Omitting this was a real bug caught
during bring-up: unscaled features fell entirely outside the trees' split
ranges and HST could not discriminate at all.

### 3.2 EWMA control chart — univariate volumetric spikes

`pyroxd.detect.ewma.EWMAControlChart`, an online form of the EWMA/Shewhart
control chart (Roberts, *Technometrics* 1959). Per continuous feature it keeps
an exponentially weighted mean and variance (recent traffic weighted more, for
drift adaptation) and scores the largest standardised deviation.

It deliberately monitors **only the five continuous magnitude features**. The
one-hot/categorical features are near-constant, so their EWMA variance collapses
and a single flip yields a meaningless, calibration-poisoning z-score — another
real bug caught during bring-up (`test_ewma_ignores_categorical_flip` guards it).
This is the detector that catches the exfiltration flow decisively (score 1.0).

### 3.3 & 3.4 Streaming Shannon entropy — collective attacks

`pyroxd.detect.entropy.EntropyDetector`, grounded in **Lakhina, Crovella & Diot,
"Mining Anomalies Using Traffic Feature Distributions", SIGCOMM 2005**.

Point-wise detectors see one flow at a time and miss attacks whose signature is
*collective* — a port scan is a burst of individually unremarkable probes. Over
a sliding window we compute Shannon entropy `H = −Σ pᵢ log₂ pᵢ` of a categorical
field and score its deviation from an EWMA baseline. Two instances watch
**destination port** (scan tell) and **destination IP** (fan-out / beacon tell).

## 4. Calibration and fusion

Each detector produces a raw score on its own scale. A
[`StreamingNormalizer`](../src/pyroxd/detect/base.py) maps it to `[0, 1]` using
a numerically stable running mean/variance (Welford) and a **one-sided
upper-tail logistic**: a *typical* point maps near 0, and probability only ramps
up as a score climbs `offset` sigma above its own baseline. The one-sided design
is essential — a plain logistic centres typical points at 0.5, which saturates
the fusion and was the cause of a 59% false-positive rate in the first
bring-up run.

The engine fuses the four calibrated scores with a **weighted noisy-OR**:

```
P(anomaly) = 1 − Π (1 − wᵢ·sᵢ)
```

Noisy-OR says "anomalous if *any* credible detector thinks so", which matches
how an analyst reasons across signals and — unlike a mean — never lets one calm
detector wash out one alarmed detector. Weights are equal by default so a
single-signal attack (e.g. a C2 beacon, visible almost solely in destination-IP
entropy) is never blinded.

An alert above the operating threshold also carries the per-detector
contributions and the top features by standardised deviation — the raw material
for the GUI's "why did this fire?" panel.

## 5. Measured performance

From `tests/test_engine_e2e.py` on the built-in labelled scenario (1500-flow
benign baseline + four interleaved attack families, seed 1):

```
recall = 0.826   steady_state_fpr = 0.0116   all 4 families detected
```

### Honest limitations

- **Window bleed.** Benign flows in the ~60-flow window immediately after an
  attack still score high because the entropy window legitimately still holds
  attack samples. In operation these are grouped with the incident; we measure
  and report steady-state FPR separately rather than hide this transient. Alert
  grouping / cooldown is a planned feature.
- **Synthetic evaluation.** Numbers are on synthetic lab traffic. Validation on
  public labelled corpora (e.g. CIC-IDS style flow datasets) is a roadmap item
  before any operational claim.
- **Flow-level only.** The engine scores flow summaries, not packet payloads;
  payload/DPI signals are out of scope for milestone 1.

## 6. Reproducing the numbers

```bash
PYTHONPATH=src python tests/test_engine_e2e.py      # recall + steady-state FPR
PYTHONPATH=src python tests/test_detectors_unit.py  # per-detector correctness
PYTHONPATH=src python -m pyroxd demo                 # live explained alert feed
```
