"""Streaming Shannon-entropy detector for distributional attacks.

Point-wise detectors (HST, EWMA) see one flow at a time and can miss attacks
whose signature is *collective*: a port scan is a burst of individually
unremarkable flows, and a DDoS is a flood of individually small ones. What
gives them away is a sudden change in the *distribution* of a categorical
field over a short window -- e.g. one source suddenly touching hundreds of
destination ports collapses the per-source destination entropy pattern.

We maintain a sliding window of recent categorical values and compute the
Shannon entropy H = -sum p_i log2 p_i over it, then score how far the current
entropy sits from its own EWMA baseline. This mirrors the entropy-based
anomaly detection used in operational NetFlow monitoring:

    A. Lakhina, M. Crovella, C. Diot, "Mining Anomalies Using Traffic Feature
    Distributions", ACM SIGCOMM 2005.

The detector is keyed on a chosen flow attribute so several instances can watch
different fields (destination port, destination IP, ...).
"""

from __future__ import annotations

import math
from collections import Counter, deque

from .base import StreamingNormalizer


class EntropyDetector:
    """Sliding-window entropy detector over one categorical attribute.

    This detector operates on raw :class:`~pyroxd.core.flow.FlowRecord` values
    rather than the numeric feature vector, because entropy is meaningful only
    over the original categories. It exposes the same calibrated-[0, 1]
    interface as :class:`~pyroxd.detect.base.Detector` via :meth:`observe`.
    """

    def __init__(self, name: str, window: int = 200) -> None:
        self.name = name
        self.window = window
        self._win: deque = deque(maxlen=window)
        self._counts: Counter = Counter()
        self._baseline = 0.0           # EWMA of recent entropy
        self._baseline_var = 1.0
        self._alpha = 0.02
        self._norm = StreamingNormalizer()
        self._n = 0

    def _entropy(self) -> float:
        total = len(self._win)
        if total == 0:
            return 0.0
        h = 0.0
        for c in self._counts.values():
            if c:
                p = c / total
                h -= p * math.log2(p)
        return h

    def observe(self, value) -> float:
        """Add one categorical ``value``; return calibrated anomaly score."""
        if len(self._win) == self.window:
            old = self._win[0]
            self._counts[old] -= 1
            if self._counts[old] == 0:
                del self._counts[old]
        self._win.append(value)
        self._counts[value] += 1

        h = self._entropy()
        self._n += 1
        if self._n <= self.window:
            # Fill the window before judging; just track the baseline.
            self._baseline = h
            return 0.0

        # Raw score = absolute deviation of current entropy from its baseline.
        raw = abs(h - self._baseline)
        diff = h - self._baseline
        self._baseline += self._alpha * diff
        return self._norm.update(raw)

    @property
    def current_entropy(self) -> float:
        return self._entropy()
