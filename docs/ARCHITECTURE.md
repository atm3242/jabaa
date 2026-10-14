# pyroXD Architecture

## Layered design

pyroXD is built in layers so that the detection engine is independent of where
flows come from and where alerts go. This is what lets the same, tested engine
run over synthetic lab traffic today and (on the roadmap) live capture or a GUI
backend tomorrow, without change.

```
            +--------------------------------------------------+
   future   |  GUI (bespoke web front end) / guided lessons     |
            +--------------------------------------------------+
                          |  Alert stream (explained)
            +--------------------------------------------------+
   now      |  DetectionEngine  (fusion + calibration + explain) |
            |    HalfSpaceTrees | EWMA | Entropy x2               |
            +--------------------------------------------------+
                          |  FlowRecord -> feature vector
            +--------------------------------------------------+
   now      |  Flow sources                                     |
            |    SyntheticTraffic (lab)   | future: capture      |
            +--------------------------------------------------+
```

## Component responsibilities

| Layer | Module | Responsibility |
|---|---|---|
| Flow source | `lab/synth.py` | Produce `FlowRecord`s (synthetic, labelled) |
| Data model | `core/flow.py` | `FlowRecord` + fixed-width feature extraction |
| Detectors | `detect/halfspace_trees.py`, `ewma.py`, `entropy.py` | Independent online anomaly scorers |
| Calibration | `detect/base.py` | Map raw scores to a comparable `[0,1]` scale |
| Engine | `detect/ensemble.py` | Fuse detectors, apply threshold/warmup, explain |
| Presentation | `cli.py` (GUI later) | Render the explained alert stream |

## Key contracts

- **`FlowRecord.features() -> np.ndarray`** is the single source of truth for
  the feature vector. `FEATURE_NAMES` is the ordered, stable label list, so an
  alert can always name the feature behind a score.
- **`Detector.observe(x) -> float`** is the uniform detector contract: consume
  one feature vector, return a calibrated `[0,1]` score, update internal state.
  Every detector owns its own calibration, so the engine treats them
  identically.
- **`DetectionEngine.process(flow) -> Alert`** is the one public call: score a
  flow, fuse, threshold, and return a fully explained `Alert`.

## Why these boundaries

- **Capture-agnostic engine.** Nothing in `detect/` imports anything about
  sockets, pcap, or the OS. Swapping the synthetic source for a live adapter is
  purely additive.
- **Bounded, streaming state everywhere.** No component stores the full stream;
  memory is constant in the number of flows seen (HST is verified by test).
- **Explainability is structural, not bolted on.** The `Alert` carries the
  per-detector contributions and the driving features, so any front end can
  explain a decision without re-deriving it.

## Cross-platform stance

The engine depends only on numpy and the Python standard library, which run
identically on Windows and macOS. No OS-specific calls, no native extensions,
no vendor runtime. Live packet capture (a later milestone) is the one place
that must become platform-aware, and it is deliberately isolated behind the
flow-source boundary so the engine stays portable.
