"""Incident correlation: turn a stream of per-flow alerts into incidents.

A per-flow alert stream is noisy by nature: one attack produces a burst of
alerts, and the window-based detectors keep firing for a short tail after the
attack ends (the "window bleed" documented in ``DETECTION_ENGINE.md``). An
analyst does not want 200 rows for one port scan -- they want *one incident*
that says "port scan, 75 flows, peaked at 1.00, 10.0.0.10, 09:14:35-09:14:41".

:class:`IncidentTracker` is a small streaming correlator that groups alerts
separated by less than ``gap_seconds`` into a single :class:`Incident`. Because
the post-attack bleed arrives within that gap, it is absorbed into the same
incident as the attack that caused it -- which is exactly the right semantics
and is what makes incident-level precision far higher than raw per-flow
precision. It keeps only the currently open incident plus a bounded history, so
memory stays constant.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

from .base import Alert

# Labels that represent an actual attack (everything else is background).
_ATTACK_LABELS = frozenset({"portscan", "synflood", "exfil", "beacon"})


@dataclass(slots=True)
class Incident:
    """A correlated group of alerts treated as one security event."""

    id: int
    start_ts: float
    end_ts: float
    n_alerts: int = 0
    peak_score: float = 0.0
    label_counts: Counter = field(default_factory=Counter)
    driver_counts: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def dominant_label(self) -> str:
        """Best single description of the incident.

        Prefer the most common *attack* label among member alerts; fall back to
        the most common label overall. This makes an incident of "port scan +
        benign bleed" read as ``portscan``, not ``benign``.
        """
        attack = Counter({k: v for k, v in self.label_counts.items()
                          if k in _ATTACK_LABELS})
        pool = attack or self.label_counts
        return pool.most_common(1)[0][0] if pool else "unknown"

    @property
    def is_attack(self) -> bool:
        """True if the incident contains any genuine attack flow (for eval)."""
        return any(k in _ATTACK_LABELS for k in self.label_counts)

    def top_drivers(self, k: int = 3) -> list[tuple[str, int]]:
        return self.driver_counts.most_common(k)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "start_ts": round(self.start_ts, 3),
            "end_ts": round(self.end_ts, 3),
            "duration": round(self.duration, 3),
            "n_alerts": self.n_alerts,
            "peak_score": round(self.peak_score, 4),
            "label": self.dominant_label,
            "is_attack": self.is_attack,
            "top_drivers": self.top_drivers(),
        }


class IncidentTracker:
    """Streaming correlator grouping nearby alerts into incidents.

    Parameters
    ----------
    gap_seconds:
        Maximum time between consecutive alerts for them to belong to the same
        incident. Alerts further apart start a new incident. The default (2s)
        comfortably absorbs the post-attack detection tail while still
        separating distinct episodes.
    history:
        How many closed incidents to retain for inspection/telemetry.
    """

    def __init__(self, gap_seconds: float = 2.0, history: int = 256) -> None:
        self.gap_seconds = gap_seconds
        self._open: Incident | None = None
        self._closed: deque[Incident] = deque(maxlen=history)
        self._next_id = 1

    def observe(self, alert: Alert) -> Incident | None:
        """Feed one anomalous alert. Returns a newly *closed* incident, if any.

        Only call this for alerts with ``is_anomaly`` true; benign-scored flows
        do not belong to any incident and must not extend one.
        """
        closed: Incident | None = None
        if self._open is not None and (alert.ts - self._open.end_ts) > self.gap_seconds:
            closed = self._open
            self._closed.append(closed)
            self._open = None

        if self._open is None:
            self._open = Incident(id=self._next_id, start_ts=alert.ts, end_ts=alert.ts)
            self._next_id += 1

        inc = self._open
        inc.end_ts = alert.ts
        inc.n_alerts += 1
        inc.peak_score = max(inc.peak_score, alert.score)
        inc.label_counts[alert.label] += 1
        for name, _dev in alert.top_features:
            inc.driver_counts[name] += 1
        return closed

    def flush(self) -> Incident | None:
        """Close and return the currently open incident (end of stream)."""
        closed = self._open
        if closed is not None:
            self._closed.append(closed)
            self._open = None
        return closed

    @property
    def open_incident(self) -> Incident | None:
        return self._open

    def all_incidents(self) -> list[Incident]:
        """Every closed incident plus the open one, in order."""
        out = list(self._closed)
        if self._open is not None:
            out.append(self._open)
        return out
