"""Multi-seed benchmark of the pyroXD engine over the synthetic lab.

Runs the full engine across several reproducible scenarios and reports, with
mean and spread across seeds:

* **Flow-level** ROC-AUC and average precision (threshold-free quality),
* **Operating-point** recall / precision / steady-state false-positive rate at
  the configured threshold,
* **Per-family** recall (is each attack family caught?),
* **Incident-level** precision and recall after correlation -- the numbers an
  analyst actually experiences, since the window-bleed collapses into the
  incident that caused it.

External public-corpus validation (CIC-IDS / NSL-KDD lineage) remains future
work, tracked in ``ROADMAP.md``; this harness establishes the internal,
reproducible baseline that such validation will be compared against.
"""

from __future__ import annotations

import statistics as stats

import numpy as np

from ..detect.ensemble import DetectionEngine, EngineConfig
from ..lab.synth import labelled_scenario
from .metrics import average_precision, confusion_at, roc_auc

ATTACK_LABELS = ("portscan", "synflood", "exfil", "beacon")
_RECOVERY = 60  # flows after an attack still inside the entropy window's memory


def _recovery_mask(labels: list[str]) -> np.ndarray:
    mask = np.zeros(len(labels), dtype=bool)
    for i, lbl in enumerate(labels):
        if lbl in ATTACK_LABELS:
            mask[i + 1: i + 1 + _RECOVERY] = True
    return mask


def run_one(seed: int, config: EngineConfig | None = None) -> dict:
    """Run the engine over one scenario; return per-run metrics."""
    cfg = config or EngineConfig()
    flows = labelled_scenario(seed=seed)
    engine = DetectionEngine(cfg)
    alerts = [engine.process(f) for f in flows]
    engine._incidents.flush()  # close the final open incident

    labels = [f.label for f in flows]
    scores = np.array([a.score for a in alerts])
    is_attack = np.array([lbl in ATTACK_LABELS for lbl in labels])
    warm = np.arange(len(flows)) < cfg.warmup
    recovery = _recovery_mask(labels)

    # Threshold-free quality, evaluated past warmup.
    ev = ~warm
    auc = roc_auc(scores[ev], is_attack[ev])
    ap = average_precision(scores[ev], is_attack[ev])

    # Operating point, with steady-state FPR (exclude post-attack recovery).
    at = confusion_at(scores[ev], is_attack[ev], cfg.threshold)
    steady = ev & ~recovery & ~is_attack
    pred = scores >= cfg.threshold
    fp_steady = int(np.sum(pred & steady))
    tn_steady = int(np.sum(~pred & steady))
    steady_fpr = fp_steady / (fp_steady + tn_steady) if (fp_steady + tn_steady) else 0.0

    # Per-family recall.
    family = {}
    for fam in ATTACK_LABELS:
        idx = np.array([lbl == fam for lbl in labels])
        hit = int(np.sum(pred & idx))
        family[fam] = hit / int(idx.sum()) if idx.sum() else 0.0

    # Incident-level precision/recall after correlation.
    incidents = engine.incidents()
    n_inc = len(incidents)
    n_attack_inc = sum(1 for inc in incidents if inc.is_attack)
    inc_precision = n_attack_inc / n_inc if n_inc else 0.0
    fams_covered = {inc.dominant_label for inc in incidents if inc.is_attack}
    inc_recall = len(fams_covered & set(ATTACK_LABELS)) / len(ATTACK_LABELS)

    return {
        "seed": seed,
        "auc": auc, "ap": ap,
        "recall": at["recall"], "precision": at["precision"],
        "steady_fpr": steady_fpr,
        "family_recall": family,
        "n_incidents": n_inc,
        "incident_precision": inc_precision,
        "incident_recall": inc_recall,
    }


def run_benchmark(seeds=(1, 2, 3, 4, 5), config: EngineConfig | None = None) -> dict:
    runs = [run_one(s, config) for s in seeds]

    def agg(key):
        vals = [r[key] for r in runs]
        mean = stats.fmean(vals)
        sd = stats.pstdev(vals) if len(vals) > 1 else 0.0
        return {"mean": mean, "std": sd}

    fam_agg = {}
    for fam in ATTACK_LABELS:
        vals = [r["family_recall"][fam] for r in runs]
        fam_agg[fam] = {"mean": stats.fmean(vals),
                        "std": stats.pstdev(vals) if len(vals) > 1 else 0.0}

    return {
        "seeds": list(seeds),
        "flow": {"auc": agg("auc"), "ap": agg("ap"),
                 "recall": agg("recall"), "precision": agg("precision"),
                 "steady_fpr": agg("steady_fpr")},
        "family_recall": fam_agg,
        "incident": {"precision": agg("incident_precision"),
                     "recall": agg("incident_recall"),
                     "count": agg("n_incidents")},
        "runs": runs,
    }


def format_report(result: dict) -> str:
    def pm(a):
        return f"{a['mean']:.3f} +/- {a['std']:.3f}"

    f = result["flow"]
    inc = result["incident"]
    lines = [
        "pyroXD evaluation report",
        "=" * 52,
        f"seeds: {result['seeds']}",
        "",
        "Flow-level (threshold-free):",
        f"  ROC-AUC            {pm(f['auc'])}",
        f"  Average precision  {pm(f['ap'])}",
        "",
        "Operating point:",
        f"  Recall             {pm(f['recall'])}",
        f"  Precision          {pm(f['precision'])}",
        f"  Steady-state FPR   {pm(f['steady_fpr'])}",
        "",
        "Per-family recall:",
    ]
    for fam, a in result["family_recall"].items():
        lines.append(f"  {fam:10s}       {pm(a)}")
    lines += [
        "",
        "Incident-level (after correlation):",
        f"  Incidents / run    {pm(inc['count'])}",
        f"  Incident precision {pm(inc['precision'])}",
        f"  Incident recall    {pm(inc['recall'])}",
    ]
    return "\n".join(lines)
