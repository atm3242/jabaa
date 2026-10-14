# Roadmap

pyroXD is built in vertical slices: each milestone is a working, tested increment
rather than a big-bang release. This keeps every claim backed by runnable code.

## Milestone 1 — Detection engine (DONE)

- [x] Flow data model + feature extraction (`core/flow.py`)
- [x] Streaming Half-Space Trees from the IJCAI 2011 paper (`detect/halfspace_trees.py`)
- [x] EWMA control-chart detector (`detect/ewma.py`)
- [x] Streaming Shannon-entropy detectors (`detect/entropy.py`)
- [x] One-sided streaming calibration + noisy-OR fusion + explanations (`detect/ensemble.py`)
- [x] Self-contained labelled synthetic lab (`lab/synth.py`)
- [x] Unit + end-to-end detection-quality tests (`tests/`)
- [x] CLI live alert feed (`python -m pyroxd demo`)
- [x] Architecture, engine, literature, tools, and safety docs

**Measured:** 0.83 recall across four attack families at 1.2% steady-state FPR
on the built-in scenario.

## Milestone 2 — Evaluation & robustness

- [ ] Validate on public labelled flow corpora (CIC-IDS / NSL-KDD lineage)
- [ ] Alert grouping / incident cooldown to resolve post-attack window bleed
- [ ] Precision/recall/ROC reporting harness with per-family breakdown
- [ ] Config file + tunable operating point with documented trade-offs

## Milestone 3 — Bespoke GUI (DONE)

- [x] Local web backend driving `DetectionEngine` over a flow stream (pure
      stdlib `http.server`, Server-Sent Events; `python -m pyroxd serve`)
- [x] Real-time visualisations: live score timeline, per-detector contribution
      breakdown, entropy gauges, alert stream with drill-down
- [x] A custom, non-template visual design (no stock framework defaults)
- [x] A guided, click-through "help / walkthrough" of every view
- [ ] Remaining: live flow table filtering, incident grouping view, theming UI

## Milestone 4 — Live capture (passive, opt-in)

- [ ] Platform capture adapters (Windows/macOS), passive observe-only
- [ ] Flow assembly from packets behind the existing flow-source boundary
- [ ] Explicit per-session opt-in and interface selection (see `SAFETY.md`)

## Milestone 5 — Guided lab curriculum

- [ ] Structured lessons: baseline → detection → tuning → evaluation
- [ ] Each lesson reproducible against the synthetic lab with checks
- [ ] Mitigation module — opt-in, lab-confined, audited (see `SAFETY.md`)

## Non-goals (explicitly out of scope)

- Offensive tooling aimed at real external systems.
- Any dependency on a proprietary vendor, paid license, or external AI service.
- Marketing numbers: every performance figure must come from a rerunnable test.
