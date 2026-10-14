# The pyroXD Console (GUI)

A bespoke, hand-authored web console that renders the detection engine's live
output. It is served by a **pure standard-library backend** (no web framework)
and a **framework-free front end** (vanilla JS + hand-drawn canvas), so the only
dependency remains numpy.

## Running it

```bash
PYTHONPATH=src python -m pyroxd serve
# then open http://127.0.0.1:8787
```

Options:

```bash
python -m pyroxd serve --port 9000      # choose a port
# In the browser, tune the live stream via URL query:
#   http://127.0.0.1:8787/?rate=120&seed=3
#   rate = flows per second, seed = which synthetic scenario
```

## What it shows

| Panel | What it renders | Backed by |
|---|---|---|
| **Threat Timeline** | Fused anomaly score (0–1) scrolling in real time, coloured green→ember→red by severity, with the dashed alert threshold and per-family anomaly markers | `Alert.score`, `Alert.is_anomaly`, `Alert.label` |
| **Detector Consensus** | Four animated bars, one per detector, showing each detector's opinion on the latest flow | `Alert.contributions` |
| **Distribution Entropy** | Two live arc gauges: Shannon entropy of destination ports and destination IPs | `DetectionEngine.telemetry()` |
| **Alert Stream** | Newest-first table of flagged flows with the detectors and features that drove each; click a row to expand the flow detail | `Alert` + flow summary |
| **Help (`?`)** | A guided, numbered walkthrough of every panel | static overlay |

## How the data gets there

The backend (`pyroxd/gui/server.py`) runs the `DetectionEngine` over the
synthetic lab and pushes one JSON frame per flow over **Server-Sent Events**
(`/api/stream`). The front end (`pyroxd/gui/static/app.js`) consumes it with the
native `EventSource` API and redraws the canvases on `requestAnimationFrame`.
SSE was chosen specifically because it needs nothing beyond the standard
library — a long-lived HTTP response, no WebSocket dependency.

```
DetectionEngine → Alert (JSON frame) → SSE /api/stream → EventSource → canvas/DOM
```

## Design notes

The visual language is deliberately custom — an ember-on-charcoal SOC console
with beveled panels, hairline accents, a living grid backdrop, and monospace
telemetry — rather than any stock framework theme. Timeline and gauges are drawn
by hand on `<canvas>`; the detector bars and alert flashes are CSS transitions.
The palette and layout tokens live at the top of
`pyroxd/gui/static/style.css` for easy retheming.

## Safety

The console only ever renders traffic from the self-contained synthetic lab (see
[`SAFETY.md`](SAFETY.md)). It binds to `127.0.0.1` by default and performs no
outbound calls. It is an observability surface: it displays scores, it does not
take any action against any system.
