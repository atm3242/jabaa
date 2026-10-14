"""Shared contracts for the pyroXD streaming detection engine.

Every detector is an *online* algorithm: it consumes one feature vector at a
time, returns an anomaly score for that point, and updates its own state. This
is the defining constraint of real-time intrusion/anomaly detection -- we never
get to see the whole dataset, memory must stay bounded, and the data
distribution drifts. The base classes here encode that contract so detectors
compose cleanly in :mod:`pyroxd.detect.ensemble`.

Scores produced by a detector are *raw* and on each detector's own scale. The
:class:`StreamingNormalizer` turns any raw score into a calibrated [0, 1]
anomaly probability using an online estimate of the score distribution, so the
ensemble can fuse heterogeneous detectors without hand-tuned constants.
"""

from __future__ import annotations

import abc
import math
from dataclasses import dataclass, field

import numpy as np


@dataclass(slots=True)
class Alert:
    """A single scored observation emitted by the engine."""

    ts: float
    score: float                       # fused anomaly probability in [0, 1]
    is_anomaly: bool                   # score crossed the operating threshold
    contributions: dict[str, float]    # detector name -> its [0, 1] score
    top_features: list[tuple[str, float]] = field(default_factory=list)
    label: str = "unknown"             # ground truth passed through for eval


class Detector(abc.ABC):
    """Base class for an online anomaly detector.

    Subclasses implement :meth:`_score_and_update`. The public :meth:`observe`
    wraps it so the detector is also responsible for calibrating its own raw
    score into [0, 1] via an owned :class:`StreamingNormalizer`. Keeping
    calibration inside the detector means the ensemble treats every detector
    identically.
    """

    name: str = "detector"

    def __init__(self) -> None:
        self._norm = StreamingNormalizer()

    @abc.abstractmethod
    def _score_and_update(self, x: np.ndarray) -> float:
        """Return a raw anomaly score for ``x`` and fold ``x`` into state.

        Higher must mean *more anomalous*. The scale is arbitrary and may be
        unbounded; calibration is handled by the base class.
        """

    def observe(self, x: np.ndarray) -> float:
        """Score one feature vector and return a calibrated probability [0, 1]."""
        raw = self._score_and_update(x)
        return self._norm.update(raw)


class StreamingNormalizer:
    """Calibrate an unbounded raw score to [0, 1] online.

    We maintain a numerically stable running mean and variance of the raw
    scores (Welford's algorithm) and map a new score through a logistic of its
    standardised value. This gives a smooth, monotonic, distribution-aware
    probability without storing any history, so a score that is, say, three
    standard deviations above the typical raw score lands near 0.95 regardless
    of the detector's native units.
    """

    def __init__(self, warmup: int = 30, offset: float = 2.5,
                 slope: float = 1.5) -> None:
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0            # sum of squared deviations (Welford)
        self._warmup = warmup
        self._offset = offset     # how many sigma above typical before we worry
        self._slope = slope       # steepness of the suspicion ramp

    def update(self, raw: float) -> float:
        if not math.isfinite(raw):
            raw = 0.0
        self._n += 1
        delta = raw - self._mean
        self._mean += delta / self._n
        self._m2 += delta * (raw - self._mean)

        # During warmup we have no reliable spread yet; stay non-committal.
        if self._n < self._warmup:
            return 0.0

        var = self._m2 / (self._n - 1)
        std = math.sqrt(var) if var > 1e-12 else 1e-6
        z = (raw - self._mean) / std
        # One-sided upper-tail logistic: a *typical* point (z ~ 0) maps near 0,
        # and probability only ramps up as the raw score climbs ``offset`` sigma
        # above its own running baseline. This is what keeps benign traffic
        # quiet so the noisy-OR fusion does not saturate. Lower deviations
        # (quieter than usual) are never anomalous, hence the one-sided design.
        return 1.0 / (1.0 + math.exp(-self._slope * (z - self._offset)))

    @property
    def count(self) -> int:
        return self._n
