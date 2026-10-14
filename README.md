# pyroXD

**A self-contained, from-scratch real-time anomaly / intrusion detection engine
and controlled security lab.**

pyroXD is being built as a teaching-grade *and* operations-grade platform for
network anomaly and intrusion detection. Its flagship is a streaming,
unsupervised **real-time detection engine** that scores a live flow stream,
explains every alert, and adapts to drift — implemented in pure Python + numpy
with **no third-party ML framework, no proprietary vendor, no external AI
service, and no telemetry**.

> **Status: milestone 1 — the detection engine.** This repository currently
> contains the working, tested detection core and a self-contained synthetic
> lab. The bespoke GUI, live capture adapters, and guided lessons are later
> milestones (see [`docs/ROADMAP.md`](docs/ROADMAP.md)). Everything claimed in
> this README is implemented and covered by tests you can run now.

---

## What works today

- **Multi-detector streaming engine** (`pyroxd.detect.ensemble.DetectionEngine`)
  that fuses four complementary online detectors and emits an explained
  [`Alert`](src/pyroxd/detect/base.py) per flow.
- **Half-Space Trees** (Tan, Ting & Liu, IJCAI 2011) — the streaming,
  constant-memory one-class core, implemented from the paper.
- **EWMA control chart** for volumetric spikes, and two **streaming Shannon
  entropy** detectors (Lakhina et al., SIGCOMM 2005) for collective attacks.
- **Self-contained synthetic lab** that fabricates labelled benign traffic and
  four injectable attack families (port scan, SYN flood, data exfiltration, C2
  beacon) entirely in memory — no sockets, no real hosts.
- Measured quality on the built-in labelled scenario: **0.83 recall across all
  four attack families with a 1.2% steady-state false-positive rate** (see the
  e2e test output).
- **Bespoke live web console** (`python -m pyroxd serve`) — a hand-designed
  SOC-style GUI with a real-time threat timeline, animated detector-consensus
  bars, live entropy gauges, an explained alert stream, and a guided help
  walkthrough. Pure stdlib backend + framework-free front end. See
  [`docs/GUI.md`](docs/GUI.md).
- **Incident correlation** that groups a burst of alerts (and its post-attack
  tail) into one incident — **0.91 incident precision, 1.00 incident recall**.
- **Reproducible benchmark harness** (`python -m pyroxd eval`) with pure-numpy
  ROC-AUC, average precision, per-family recall, and incident-level metrics
  across seeds. See [`docs/EVALUATION.md`](docs/EVALUATION.md).

## Quick start

```bash
# Only dependency is numpy.
python -m pip install numpy

# Run the real-time detection demo over the synthetic lab:
PYTHONPATH=src python -m pyroxd demo

# Launch the bespoke web console, then open http://127.0.0.1:8787
PYTHONPATH=src python -m pyroxd serve

# Benchmark the engine across seeds (ROC-AUC, per-family, incident-level):
PYTHONPATH=src python -m pyroxd eval

# Run the test suite (no pytest required):
PYTHONPATH=src python tests/test_detectors_unit.py
PYTHONPATH=src python tests/test_engine_e2e.py
PYTHONPATH=src python tests/test_incidents_and_eval.py
```

## Repository layout

```
src/pyroxd/
  core/flow.py            Flow data model + feature extraction (NetFlow/IPFIX-style)
  detect/base.py          Detector contract + one-sided streaming calibration
  detect/halfspace_trees.py   Streaming Half-Space Trees (flagship)
  detect/ewma.py          EWMA / Shewhart control-chart detector
  detect/entropy.py       Sliding-window Shannon-entropy detector
  detect/ensemble.py      DetectionEngine: fusion + explanation
  detect/incidents.py     Streaming alert -> incident correlation
  eval/metrics.py         Pure-numpy ROC-AUC / average precision / confusion
  eval/benchmark.py       Multi-seed benchmark + report
  gui/server.py           Pure-stdlib web backend (SSE live stream)
  gui/static/             Hand-built console front end (no framework)
  lab/synth.py            Self-contained labelled traffic & attack generator
  cli.py                  demo / serve / eval subcommands
tests/                    Runnable unit + end-to-end detection-quality tests
docs/                     Architecture, engine design, literature, tools, safety
```

## Documentation

| Doc | Purpose |
|-----|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design and data flow |
| [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) | How each detector and the fusion work, with the maths |
| [`docs/GUI.md`](docs/GUI.md) | The live web console: panels, data flow, design |
| [`docs/EVALUATION.md`](docs/EVALUATION.md) | The benchmark harness, metrics, and honest results |
| [`docs/LITERATURE.md`](docs/LITERATURE.md) | The research the design is grounded in |
| [`docs/TOOLS.md`](docs/TOOLS.md) | Every tool and dependency used, and why |
| [`docs/SAFETY.md`](docs/SAFETY.md) | The safe-by-default and lab-containment model |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What is built and what comes next |

## Design principles

1. **Safe and contained by default.** The lab fabricates traffic; it never
   attacks a real system. See [`docs/SAFETY.md`](docs/SAFETY.md).
2. **No black boxes.** Every detector is a documented, citable algorithm you
   can read, and every alert names the detectors and features that produced it.
3. **Honest engineering.** Numbers in this repo come from a test you can rerun,
   not from marketing. Known limitations are written down, not hidden.
4. **Minimal dependencies.** numpy and the Python standard library only, so the
   same code runs on Windows and macOS without a vendor runtime.
