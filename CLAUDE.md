# CLAUDE.md — working notes for pyroXD

Guidance for any AI/engineer continuing this repository.

## What this is

pyroXD is a from-scratch, real-time network anomaly/intrusion detection engine
plus a self-contained security lab and a bespoke web console. It is built in
vertical, tested milestones. See `docs/ROADMAP.md` for status.

## Hard constraints (do not break these)

1. **Dependencies: numpy + Python stdlib only.** No scikit-learn, no web
   framework, no proprietary vendor, no external AI service, no telemetry. If a
   new runtime dependency seems necessary, it almost certainly is not — the
   detectors, metrics, server, and GUI are all hand-implemented. Update
   `docs/TOOLS.md` in the same change if this ever changes.
2. **The lab is self-contained.** `pyroxd.lab.synth` fabricates traffic in
   memory. Nothing in this repo may open a socket to attack, scan, or probe a
   real host. Live capture (roadmap M4) must be passive, opt-in, and isolated
   behind the flow-source boundary. See `docs/SAFETY.md`.
3. **Every quality claim must come from a rerunnable test or `pyroxd eval`.**
   No marketing numbers. Write limitations down (see `docs/DETECTION_ENGINE.md`
   and `docs/EVALUATION.md`), don't hide them.

## Layout

```
src/pyroxd/core/flow.py        flow model + feature extraction
src/pyroxd/detect/             detectors, calibration, fusion, incidents
src/pyroxd/eval/               pure-numpy metrics + multi-seed benchmark
src/pyroxd/gui/                stdlib SSE backend + framework-free front end
src/pyroxd/lab/synth.py        synthetic labelled traffic + attacks
tests/                         plain-assert tests (also pytest-compatible)
docs/                          architecture, engine, literature, tools, safety,
                               gui, evaluation, roadmap
```

## Commands

```bash
PYTHONPATH=src python -m pyroxd demo     # text live alert feed
PYTHONPATH=src python -m pyroxd serve    # web console at http://127.0.0.1:8787
PYTHONPATH=src python -m pyroxd eval     # multi-seed benchmark report

# Tests (no pytest needed; run each file directly):
PYTHONPATH=src python tests/test_detectors_unit.py
PYTHONPATH=src python tests/test_engine_e2e.py
PYTHONPATH=src python tests/test_incidents_and_eval.py
```

## Conventions

- Detectors implement the `Detector.observe(x) -> float` contract (calibrated
  [0,1]); the engine fuses them with weighted noisy-OR. Keep new detectors
  online and constant-memory.
- `FEATURE_NAMES` in `core/flow.py` is the single source of truth for feature
  order; keep alerts explainable (name the detector and feature behind a score).
- Tests are plain-assert with a `__main__` runner so they work without pytest.
- The GUI binds `127.0.0.1` by default and must never take action against any
  system — it is an observability surface only.

## Current weak point (good next task)

Flow-level recall on the diffuse attacks (beacon especially, ~0.69 ± 0.30) is
the soft spot; incident-level recall is 1.00. A periodicity/cadence feature for
beacon-style traffic is the most valuable detector improvement. External
public-corpus validation (CIC-IDS/NSL-KDD) is the most valuable evaluation
improvement.
