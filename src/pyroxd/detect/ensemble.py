"""The pyroXD detection engine: fuse detectors into explained alerts.

This is the public entry point most callers (tests, CLI, GUI backend) use. It
owns one instance of each detector, feeds every incoming
:class:`~pyroxd.core.flow.FlowRecord` to all of them, and fuses their
calibrated [0, 1] scores into a single anomaly probability plus a breakdown of
*which* detector and *which* features drove the decision -- the raw material
for the GUI's real-time "why" panel.

Fusion is a weighted soft-OR (noisy-OR). Each detector independently answers
"how anomalous is this?"; soft-OR says the point is anomalous if *any* credible
detector thinks so, which matches how a SOC analyst reasons across signals and
avoids one calm detector washing out one alarmed one (as a plain mean would).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import numpy as np

from ..core.flow import FEATURE_NAMES, FlowRecord, feature_dim
from .base import Alert
from .entropy import EntropyDetector
from .ewma import EWMAControlChart
from .halfspace_trees import HalfSpaceTrees
from .incidents import IncidentTracker


class _StreamingMinMax:
    """Online scaler mapping each feature to [0, 1] with a warmup phase.

    Half-Space Trees assume inputs live in the unit hypercube, so we track a
    running per-feature min/max and scale incoming points into [0, 1], clamping
    anything beyond the observed range. Values are gently expanded so a new
    extreme does not collapse the scale. This is the standard streaming front
    end for HST and is what lets it actually discriminate.
    """

    def __init__(self, dim: int, warmup: int = 100) -> None:
        self._min = np.full(dim, np.inf)
        self._max = np.full(dim, -np.inf)
        self._n = 0
        self._warmup = warmup

    def scale(self, x: np.ndarray) -> tuple[np.ndarray, bool]:
        self._min = np.minimum(self._min, x)
        self._max = np.maximum(self._max, x)
        self._n += 1
        span = self._max - self._min
        span = np.where(span < 1e-9, 1.0, span)
        scaled = np.clip((x - self._min) / span, 0.0, 1.0)
        return scaled, self._n >= self._warmup


class _HSTAdapter:
    """Adapt :class:`HalfSpaceTrees` to the calibrated-score detector interface."""

    name = "half_space_trees"

    def __init__(self, dim: int, **kw) -> None:
        from .base import StreamingNormalizer
        self._hst = HalfSpaceTrees(dim, **kw)
        self._scaler = _StreamingMinMax(dim)
        self._norm = StreamingNormalizer()

    def observe(self, x: np.ndarray) -> float:
        scaled, ready = self._scaler.scale(x)
        raw = self._hst.score_and_update(scaled)
        if not ready:
            return 0.0
        return self._norm.update(raw)


@dataclass(slots=True)
class EngineConfig:
    threshold: float = 0.90            # fused score above this => alert
    hst_trees: int = 25
    hst_depth: int = 15
    hst_window: int = 250
    seed: int | None = 7
    # Suppress alerting for the first ``warmup`` flows while every detector
    # establishes its baseline (scores are still computed and returned, just
    # never flagged). Without this the first unusual-but-benign flows, judged
    # against an empty baseline, would fire spuriously.
    warmup: int = 200
    # Alerts separated by less than this many seconds are correlated into one
    # incident (see pyroxd.detect.incidents).
    incident_gap: float = 2.0
    # Per-detector fusion weights. Left equal by default: the noisy-OR fusion
    # already lets any single confident detector raise the alarm, so capping a
    # detector's weight would only blind the engine to attacks only it sees
    # (e.g. a C2 beacon, which shows up almost solely in destination-IP
    # entropy). Override to bias the ensemble for a specific deployment.
    weights: dict | None = None

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)

    def save(self, path) -> None:
        """Persist the operating point to a JSON file."""
        import json
        from pathlib import Path
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def from_dict(cls, d: dict) -> "EngineConfig":
        # Accept only known fields so an unrelated JSON cannot inject attributes.
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    @classmethod
    def load(cls, path) -> "EngineConfig":
        """Load an operating point previously written by :meth:`save`."""
        import json
        from pathlib import Path
        return cls.from_dict(json.loads(Path(path).read_text()))


class DetectionEngine:
    """Online, multi-detector anomaly engine over a flow stream."""

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.cfg = config or EngineConfig()
        dim = feature_dim()
        self._hst = _HSTAdapter(
            dim,
            n_trees=self.cfg.hst_trees,
            depth=self.cfg.hst_depth,
            window=self.cfg.hst_window,
            seed=self.cfg.seed,
        )
        self._ewma = EWMAControlChart(dim)
        # Two entropy views: destination port (scan tell) and destination IP
        # (one-to-many fan-out, a DDoS/sweep tell).
        self._ent_port = EntropyDetector("entropy_dport", window=200)
        self._ent_dstip = EntropyDetector("entropy_dstip", window=200)

        self._weights = self.cfg.weights or {
            "half_space_trees": 1.0,
            "ewma": 1.0,
            "entropy_dport": 1.0,
            "entropy_dstip": 1.0,
        }
        self._recent: deque[Alert] = deque(maxlen=512)
        self._incidents = IncidentTracker(gap_seconds=self.cfg.incident_gap)
        self._processed = 0

    def process(self, flow: FlowRecord) -> Alert:
        """Score one flow and return its :class:`Alert`."""
        x = flow.features()
        contributions = {
            "half_space_trees": self._hst.observe(x),
            "ewma": self._ewma.observe(x),
            "entropy_dport": self._ent_port.observe(flow.dst_port),
            "entropy_dstip": self._ent_dstip.observe(flow.dst_ip),
        }

        # Weighted noisy-OR: P(anomaly) = 1 - prod(1 - w_i * s_i). Weights are
        # normalised to [0, 1] so a single maxed-out detector can still fire.
        prod = 1.0
        wmax = max(self._weights.values())
        for name, s in contributions.items():
            w = self._weights.get(name, 1.0) / wmax
            prod *= (1.0 - w * s)
        fused = 1.0 - prod

        self._processed += 1
        warming_up = self._processed <= self.cfg.warmup

        top_features = self._explain(x)
        alert = Alert(
            ts=flow.ts,
            score=fused,
            is_anomaly=(fused >= self.cfg.threshold) and not warming_up,
            contributions=contributions,
            top_features=top_features,
            label=flow.label,
        )
        self._recent.append(alert)
        if alert.is_anomaly:
            self._incidents.observe(alert)
        return alert

    def _explain(self, x: np.ndarray, k: int = 3) -> list[tuple[str, float]]:
        """Name the top-k features by standardised deviation (from EWMA state)."""
        devs = self._ewma.feature_deviations(x)
        order = np.argsort(devs)[::-1][:k]
        return [(FEATURE_NAMES[i], float(devs[i])) for i in order]

    @property
    def recent(self) -> list[Alert]:
        return list(self._recent)

    def incidents(self):
        """All correlated incidents seen so far (closed + currently open)."""
        return self._incidents.all_incidents()

    def telemetry(self) -> dict:
        """A live snapshot of internal detector state, for the GUI gauges.

        Exposes the two entropy detectors' current sliding-window entropy (a
        value the point-wise detectors do not surface), plus how far through
        warmup the engine is. Pure read of already-computed state; cheap to
        call once per processed flow.
        """
        return {
            "processed": self._processed,
            "warmup": self.cfg.warmup,
            "warming_up": self._processed <= self.cfg.warmup,
            "threshold": self.cfg.threshold,
            "entropy_dport": self._ent_port.current_entropy,
            "entropy_dstip": self._ent_dstip.current_entropy,
            "n_incidents": len(self._incidents.all_incidents()),
        }
