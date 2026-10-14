"""Tests for incident correlation, metrics, config persistence, and the
benchmark. Runs under pytest or standalone via ``python3``.
"""

from __future__ import annotations

import os
import sys
import tempfile

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyroxd.detect.base import Alert  # noqa: E402
from pyroxd.detect.ensemble import EngineConfig  # noqa: E402
from pyroxd.detect.incidents import IncidentTracker  # noqa: E402
from pyroxd.eval.benchmark import run_benchmark  # noqa: E402
from pyroxd.eval.metrics import average_precision, confusion_at, roc_auc  # noqa: E402


def _alert(ts, label, score=0.95):
    return Alert(ts=ts, score=score, is_anomaly=True, contributions={},
                 top_features=[("log_bytes", 3.0)], label=label)


def test_incident_groups_burst_and_absorbs_bleed():
    """A dense attack burst plus its trailing benign bleed = one incident."""
    tr = IncidentTracker(gap_seconds=2.0)
    for i in range(40):                       # attack burst, 0.01s apart
        tr.observe(_alert(100.0 + i * 0.01, "portscan"))
    for i in range(10):                       # benign bleed right after
        tr.observe(_alert(100.5 + i * 0.02, "benign"))
    tr.flush()
    incs = tr.all_incidents()
    assert len(incs) == 1, f"expected one incident, got {len(incs)}"
    inc = incs[0]
    assert inc.dominant_label == "portscan", "attack label must win over bleed"
    assert inc.is_attack
    assert inc.n_alerts == 50


def test_incident_splits_on_time_gap():
    """Alerts separated by more than the gap form distinct incidents."""
    tr = IncidentTracker(gap_seconds=2.0)
    tr.observe(_alert(100.0, "portscan"))
    tr.observe(_alert(100.5, "portscan"))
    tr.observe(_alert(200.0, "exfil"))        # 100s later -> new incident
    tr.flush()
    incs = tr.all_incidents()
    assert len(incs) == 2
    assert {i.dominant_label for i in incs} == {"portscan", "exfil"}


def test_roc_auc_separation():
    """AUC is ~1 when positives score above negatives, 0.5 for random."""
    scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9, 1.0])
    labels = np.array([0, 0, 0, 1, 1, 1])
    assert abs(roc_auc(scores, labels) - 1.0) < 1e-9
    rng = np.random.default_rng(0)
    s = rng.random(2000)
    y = rng.integers(0, 2, 2000)
    assert abs(roc_auc(s, y) - 0.5) < 0.05


def test_average_precision_and_confusion():
    scores = np.array([0.1, 0.4, 0.35, 0.8])
    labels = np.array([0, 0, 1, 1])
    ap = average_precision(scores, labels)
    assert 0.0 <= ap <= 1.0 and ap > 0.7
    c = confusion_at(scores, labels, 0.5)
    assert c["tp"] == 1 and c["fp"] == 0  # only 0.8 crosses, and it is positive


def test_config_round_trip():
    cfg = EngineConfig(threshold=0.77, warmup=123, incident_gap=3.5)
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as fh:
        path = fh.name
    try:
        cfg.save(path)
        back = EngineConfig.load(path)
        assert back.threshold == 0.77
        assert back.warmup == 123
        assert back.incident_gap == 3.5
    finally:
        os.unlink(path)


def test_config_from_dict_ignores_unknown_keys():
    cfg = EngineConfig.from_dict({"threshold": 0.5, "evil": "x", "seed": 9})
    assert cfg.threshold == 0.5 and cfg.seed == 9
    assert not hasattr(cfg, "evil")


def test_benchmark_quality_floor():
    """The engine must clear a quality floor across multiple seeds."""
    res = run_benchmark(seeds=(1, 2, 3))
    assert res["flow"]["auc"]["mean"] >= 0.85, res["flow"]["auc"]
    assert res["incident"]["recall"]["mean"] >= 0.99, "every family must form an incident"
    assert res["incident"]["precision"]["mean"] >= 0.75, res["incident"]["precision"]
    assert res["flow"]["steady_fpr"]["mean"] <= 0.05


if __name__ == "__main__":
    for fn in [
        test_incident_groups_burst_and_absorbs_bleed,
        test_incident_splits_on_time_gap,
        test_roc_auc_separation,
        test_average_precision_and_confusion,
        test_config_round_trip,
        test_config_from_dict_ignores_unknown_keys,
        test_benchmark_quality_floor,
    ]:
        fn()
        print(f"ok: {fn.__name__}")
    print("\nOK: all incident/eval assertions passed")
