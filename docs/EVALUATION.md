# Evaluation

pyroXD ships a reproducible, from-scratch evaluation harness so every quality
claim can be regenerated rather than taken on faith.

```bash
PYTHONPATH=src python -m pyroxd eval                 # 5-seed benchmark, printed
PYTHONPATH=src python -m pyroxd eval --seeds 1 2 3   # choose seeds
PYTHONPATH=src python -m pyroxd eval --json out.json # full machine-readable report
```

## What it measures

The harness runs the full engine over several reproducible scenarios and reports
mean ± standard deviation across seeds, at three levels:

1. **Flow-level, threshold-free** — ROC-AUC and average precision. These judge
   the detector's ranking quality independent of any operating threshold.
2. **Operating point** — recall, precision, and **steady-state** false-positive
   rate at the configured threshold. Steady-state FPR excludes the short
   post-attack recovery window (see the window-bleed note in
   `DETECTION_ENGINE.md`).
3. **Incident-level, after correlation** — precision and recall once alerts are
   grouped into incidents (`pyroxd.detect.incidents`). This is the view an
   analyst actually experiences: one incident per attack episode instead of a
   burst of rows.

All metrics (`roc_auc`, `average_precision`, `confusion_at`) are implemented in
`pyroxd/eval/metrics.py` in pure numpy — no scikit-learn.

## Representative result

Five-seed benchmark at the default operating point (threshold 0.90):

```
Flow-level (threshold-free):
  ROC-AUC            0.943 +/- 0.036
  Average precision  0.736 +/- 0.086

Operating point:
  Recall             0.764 +/- 0.097
  Precision          0.581 +/- 0.101
  Steady-state FPR   0.019 +/- 0.022

Per-family recall:
  portscan           1.000 +/- 0.000
  synflood           0.657 +/- 0.187
  exfil              1.000 +/- 0.000
  beacon             0.690 +/- 0.304

Incident-level (after correlation):
  Incidents / run    18.2  +/- 6.1
  Incident precision 0.910 +/- 0.075
  Incident recall    1.000 +/- 0.000
```

### Reading the numbers honestly

- **Incident correlation is the operational win.** Per-flow recall on the
  diffuse attacks (synflood, beacon) is moderate and, for beacon, high-variance.
  But incident recall is 1.00 on every seed: each attack family always produces
  at least one incident, and 91% of incidents are genuine attacks. Operators act
  on incidents, not individual flows.
- **beacon is the current weak point** at the flow level (0.69 ± 0.30). It is a
  low-rate, low-volume signal visible almost only in destination-IP entropy;
  improving its flow-level stability (e.g. a periodicity/cadence feature) is a
  tracked follow-up.
- **These are synthetic-lab numbers.** They establish an internal, reproducible
  baseline. Validation on public labelled corpora (CIC-IDS / NSL-KDD lineage)
  remains future work (`ROADMAP.md`); it needs those datasets staged locally and
  a flow adapter, and is deliberately not faked here.

## Tuning the operating point

`EngineConfig` is serialisable, so an operating point found with the harness can
be saved and reloaded:

```python
from pyroxd.detect.ensemble import EngineConfig
EngineConfig(threshold=0.92, incident_gap=3.0).save("op.json")
cfg = EngineConfig.load("op.json")
```

Raising the threshold trades recall for precision; the `eval` output at several
thresholds is the principled way to choose it for a given deployment's tolerance
for false positives.
