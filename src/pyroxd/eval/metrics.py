"""Detection metrics, implemented from scratch in numpy (no scikit-learn).

These are the standard quality measures for an anomaly detector scored against
ground truth. Implementing them here keeps the project dependency-free and
makes every number auditable.
"""

from __future__ import annotations

import numpy as np


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """Area under the ROC curve via the rank (Mann-Whitney U) identity.

    AUC equals the probability that a randomly chosen positive is scored above
    a randomly chosen negative. Ranking handles ties correctly (average ranks)
    and is O(n log n) with no curve to integrate.
    """
    labels = labels.astype(bool)
    n_pos = int(labels.sum())
    n_neg = int((~labels).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    # Average ranks for ties so the statistic is unbiased.
    _assign_tied_ranks(scores, ranks)
    sum_pos = ranks[labels].sum()
    return (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def _assign_tied_ranks(scores: np.ndarray, ranks: np.ndarray) -> None:
    order = np.argsort(scores, kind="mergesort")
    s = scores[order]
    i = 0
    n = len(s)
    while i < n:
        j = i
        while j + 1 < n and s[j + 1] == s[i]:
            j += 1
        if j > i:
            avg = (ranks[order[i]] + ranks[order[j]]) / 2.0
            for k in range(i, j + 1):
                ranks[order[k]] = avg
        i = j + 1


def average_precision(scores: np.ndarray, labels: np.ndarray) -> float:
    """Average precision (area under the precision-recall curve).

    Computed as the sum of precision at each threshold weighted by the increase
    in recall, which is the standard AP estimator.
    """
    labels = labels.astype(bool)
    n_pos = int(labels.sum())
    if n_pos == 0:
        return float("nan")
    order = np.argsort(scores, kind="mergesort")[::-1]
    y = labels[order]
    tp = np.cumsum(y)
    fp = np.cumsum(~y)
    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / n_pos
    # Sum precision * delta-recall.
    prev_recall = 0.0
    ap = 0.0
    for p, r in zip(precision, recall):
        ap += p * (r - prev_recall)
        prev_recall = r
    return float(ap)


def confusion_at(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    """TP/FP/FN/TN and the usual rates at a fixed operating threshold."""
    labels = labels.astype(bool)
    pred = scores >= threshold
    tp = int(np.sum(pred & labels))
    fp = int(np.sum(pred & ~labels))
    fn = int(np.sum(~pred & labels))
    tn = int(np.sum(~pred & ~labels))
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": recall, "precision": precision, "fpr": fpr}
