"""Unit tests for the individual streaming detectors.

These isolate each algorithm from the ensemble so a regression points at the
exact component. Runs under pytest or standalone via ``python3``.
"""

from __future__ import annotations

import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyroxd.detect.base import StreamingNormalizer  # noqa: E402
from pyroxd.detect.entropy import EntropyDetector  # noqa: E402
from pyroxd.detect.ewma import EWMAControlChart  # noqa: E402
from pyroxd.detect.halfspace_trees import HalfSpaceTrees  # noqa: E402


def test_hst_scores_outlier_above_inliers():
    """A point far from the training cluster must score strictly higher."""
    rng = np.random.default_rng(0)
    hst = HalfSpaceTrees(dim=4, n_trees=30, depth=12, window=200, seed=1)
    # Train on a tight cluster near the origin corner of the unit cube.
    for _ in range(600):
        hst.score_and_update(rng.normal(0.2, 0.03, size=4).clip(0, 1))
    inlier = np.full(4, 0.2)
    outlier = np.full(4, 0.9)
    s_in = np.mean([hst.score(inlier) for _ in range(5)])
    s_out = np.mean([hst.score(outlier) for _ in range(5)])
    print(f"HST inlier={s_in:.3f} outlier={s_out:.3f}")
    assert s_out > s_in, "outlier should score higher than inlier"


def test_hst_constant_memory():
    """Node arrays must not grow as the stream advances (bounded memory)."""
    hst = HalfSpaceTrees(dim=3, n_trees=5, depth=6, window=50, seed=1)
    before = hst._mass_ref.nbytes + hst._mass_lat.nbytes
    for _ in range(5000):
        hst.score_and_update(np.random.random(3))
    after = hst._mass_ref.nbytes + hst._mass_lat.nbytes
    assert before == after, "HST memory footprint must be constant"


def test_ewma_flags_magnitude_spike():
    """EWMA must flag a large jump in a continuous feature but not steady data."""
    det = EWMAControlChart(dim=5)
    rng = np.random.default_rng(0)
    scores = []
    for _ in range(400):
        x = rng.normal(5.0, 0.5, size=5)
        scores.append(det.observe(x))
    # A 10-sigma spike on feature 0.
    spike = np.array([50.0, 5.0, 5.0, 5.0, 5.0])
    spike_score = det.observe(spike)
    # Typical traffic stays calm: we check the 95th percentile rather than the
    # max, because the max over 5 features x 200 samples of a Gaussian will
    # occasionally hit ~3 sigma by chance -- which is precisely why the engine
    # fuses several detectors and thresholds instead of trusting EWMA alone.
    steady_p95 = float(np.percentile(scores[200:], 95))
    print(f"EWMA steady_p95={steady_p95:.3f} spike={spike_score:.3f}")
    assert spike_score > 0.9, "large magnitude spike should score high"
    assert steady_p95 < 0.6, "95% of steady traffic should stay calm"
    assert spike_score > steady_p95, "spike must out-score typical traffic"


def test_ewma_ignores_categorical_flip():
    """A flip in a one-hot (non-monitored) feature must not spike the score."""
    det = EWMAControlChart(dim=10)  # defaults monitor indices 0..4 only
    rng = np.random.default_rng(1)
    for _ in range(300):
        x = np.concatenate([rng.normal(5, 0.3, 5), [1, 0, 0, 0, 0]])
        det.observe(x)
    # Hold the continuous part exactly at the baseline mean so the only change
    # is the one-hot flip; EWMA ignores those indices, so it must stay calm.
    flipped = np.concatenate([np.full(5, 5.0), [0, 1, 0, 1, 1]])
    assert det.observe(flipped) < 0.5, "categorical flip must not alarm EWMA"


def test_entropy_detects_distribution_collapse():
    """Entropy detector should react when a varied stream collapses to one value."""
    det = EntropyDetector("dport", window=100)
    rng = np.random.default_rng(0)
    for _ in range(400):
        det.observe(int(rng.integers(0, 1000)))  # high-entropy baseline
    # Now collapse to a single destination (as in a flood to one port).
    collapse_scores = [det.observe(80) for _ in range(100)]
    print(f"entropy collapse peak={max(collapse_scores):.3f}")
    assert max(collapse_scores) > 0.5, "entropy collapse should raise the score"


def test_normalizer_is_one_sided():
    """Below-average raw scores must stay near zero; only upper-tail alarms."""
    n = StreamingNormalizer(warmup=30)
    out = [n.update(v) for v in np.random.default_rng(0).normal(0, 1, 500)]
    # Feed a strong upper-tail value and a strong lower-tail value.
    high = n.update(8.0)
    low = n.update(-8.0)
    print(f"normalizer high={high:.3f} low={low:.3f}")
    assert high > 0.9, "far upper-tail should map near 1"
    assert low < 0.05, "far lower-tail should map near 0 (one-sided)"


if __name__ == "__main__":
    for fn in [
        test_hst_scores_outlier_above_inliers,
        test_hst_constant_memory,
        test_ewma_flags_magnitude_spike,
        test_ewma_ignores_categorical_flip,
        test_entropy_detects_distribution_collapse,
        test_normalizer_is_one_sided,
    ]:
        fn()
    print("\nOK: all detector unit assertions passed")
