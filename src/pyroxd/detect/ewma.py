"""EWMA control-chart detector.

A classic, cheap, and interpretable online detector. For each feature we keep
an exponentially weighted moving average and variance (so recent traffic counts
more than ancient traffic, giving graceful drift adaptation). A point's raw
score is the largest standardised deviation across all features -- an
EWMA-smoothed analogue of a Shewhart control chart. It excels at exactly the
cases Half-Space Trees is weakest on: a single feature blowing out, such as an
exfiltration flow that is thousands of times larger than normal.

Reference: S.W. Roberts, "Control Chart Tests Based on Geometric Moving
Averages", Technometrics 1959 -- the EWMA chart, still a workhorse of
statistical process control and network baselining.
"""

from __future__ import annotations

import numpy as np

from .base import Detector


class EWMAControlChart(Detector):
    name = "ewma"

    # Indices into the feature vector that carry continuous *magnitude*. An
    # EWMA/Shewhart control chart is defined for continuous measurements; the
    # categorical one-hots (protocol, syn_ratio, port rank) are near-constant,
    # so their variance collapses and a lone flip yields a meaningless z-score
    # that poisons calibration. Those signals belong to HST and the entropy
    # detectors instead. Defaults to the five log-scaled volumetric features.
    CONTINUOUS = (0, 1, 2, 3, 4)
    # Floor on the standard deviation so a feature that is briefly constant
    # during warmup cannot blow a deviation up to infinity.
    STD_FLOOR = 1e-2

    def __init__(self, dim: int, alpha: float = 0.02,
                 indices: tuple[int, ...] | None = None) -> None:
        """``alpha`` is the EWMA smoothing factor: smaller = longer memory."""
        super().__init__()
        self.alpha = alpha
        self._idx = np.array(self.CONTINUOUS if indices is None else indices)
        self._mean = np.zeros(dim)
        self._var = np.ones(dim)       # start at unit variance to avoid div-by-0
        self._initialised = False

    def _score_and_update(self, x: np.ndarray) -> float:
        if not self._initialised:
            # Seed the baseline with the first point so we don't flag it against
            # an all-zero mean.
            self._mean = x.astype(np.float64).copy()
            self._initialised = True
            return 0.0

        std = np.sqrt(self._var)
        std = np.where(std < self.STD_FLOOR, self.STD_FLOOR, std)
        z = np.abs(x - self._mean) / std
        raw = float(np.max(z[self._idx]))  # worst continuous-feature deviation

        # EWMA update of mean and variance (West's online form).
        diff = x - self._mean
        incr = self.alpha * diff
        self._mean = self._mean + incr
        self._var = (1.0 - self.alpha) * (self._var + diff * incr)
        return raw

    def feature_deviations(self, x: np.ndarray) -> np.ndarray:
        """Per-feature standardised deviations, for the alert "why" panel."""
        std = np.sqrt(self._var)
        std = np.where(std < self.STD_FLOOR, self.STD_FLOOR, std)
        return np.abs(x - self._mean) / std
