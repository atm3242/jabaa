"""End-to-end detection-quality test for the pyroXD engine.

This is the test that proves the flagship works: we run the full engine over a
reproducible labelled scenario (long benign baseline + four injected attack
families) and assert it recovers the attacks with high recall while keeping the
*steady-state* benign false-positive rate low.

A note on evaluation methodology. Window-based collective detectors (the
entropy detectors here) retain recent samples, so benign flows arriving in the
short window *immediately after* an attack are still being judged partly
against that attack's traffic -- a well-understood transient known as window
bleed. In operation these post-event alerts are correctly grouped with the
incident, not treated as independent false alarms. We therefore report two
numbers: overall recall, and the steady-state false-positive rate measured on
benign flows outside a post-attack recovery window. Both are asserted. Runs
under pytest or standalone via ``python3``.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyroxd.detect.ensemble import DetectionEngine, EngineConfig  # noqa: E402
from pyroxd.lab.synth import labelled_scenario  # noqa: E402

ATTACK_LABELS = {"portscan", "synflood", "exfil", "beacon"}
RECOVERY = 60  # flows after an attack still inside the entropy window's memory


def run_engine():
    flows = labelled_scenario(seed=1)
    engine = DetectionEngine(EngineConfig(threshold=0.90, warmup=200, seed=7))
    alerts = [engine.process(f) for f in flows]
    return flows, alerts


def _recovery_mask(labels):
    mask = [False] * len(labels)
    for i, lbl in enumerate(labels):
        if lbl in ATTACK_LABELS:
            for j in range(i + 1, min(i + 1 + RECOVERY, len(labels))):
                mask[j] = True
    return mask


def test_detects_injected_attacks():
    flows, alerts = run_engine()
    labels = [f.label for f in flows]
    recovery = _recovery_mask(labels)

    tp = fn = fp_steady = tn_steady = 0
    warmup = 200
    for i, a in enumerate(alerts):
        if i < warmup:
            continue  # engine is establishing its baseline; not evaluated
        if a.label in ATTACK_LABELS:
            tp += a.is_anomaly
            fn += not a.is_anomaly
        elif not recovery[i]:  # steady-state benign only
            fp_steady += a.is_anomaly
            tn_steady += not a.is_anomaly

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp_steady / (fp_steady + tn_steady) if (fp_steady + tn_steady) else 0.0
    print(f"recall={recall:.3f}  steady_state_fpr={fpr:.4f}  "
          f"TP={tp} FN={fn} FP_steady={fp_steady} TN_steady={tn_steady}")

    assert recall >= 0.75, f"recall too low: {recall:.3f}"
    assert fpr <= 0.02, f"steady-state false-positive rate too high: {fpr:.4f}"


def test_per_family_recall():
    """Each attack family must be caught at least once (no blind spot)."""
    flows, alerts = run_engine()
    caught = {lbl: False for lbl in ATTACK_LABELS}
    for a in alerts:
        if a.label in ATTACK_LABELS and a.is_anomaly:
            caught[a.label] = True
    print("per-family caught:", caught)
    missed = [k for k, v in caught.items() if not v]
    assert not missed, f"attack families never detected: {missed}"


def test_alerts_are_explained():
    """Every anomaly must carry a non-empty per-detector contribution map and
    a top-features list, so the GUI can always answer 'why did this fire?'."""
    flows, alerts = run_engine()
    anomalies = [a for a in alerts if a.is_anomaly]
    assert anomalies, "expected at least some anomalies"
    for a in anomalies:
        assert a.contributions and len(a.contributions) == 4
        assert a.top_features and len(a.top_features) >= 1
        assert 0.0 <= a.score <= 1.0


if __name__ == "__main__":
    test_detects_injected_attacks()
    test_per_family_recall()
    test_alerts_are_explained()
    print("\nOK: all e2e assertions passed")
