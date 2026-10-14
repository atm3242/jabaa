"""Flow data model and feature extraction for the pyroXD detection engine.

A :class:`FlowRecord` is a compact, vendor-neutral summary of a single
network conversation, modelled on the fields common to Cisco NetFlow v9 and
the IETF IPFIX information model (RFC 7011/7012). We deliberately keep the
record small and numeric-friendly so that the streaming detectors in
``pyroxd.detect`` can turn it into a fixed-length feature vector cheaply.

Nothing in this module touches a real network interface. Flows arrive either
from the synthetic lab generator (:mod:`pyroxd.lab.synth`) or, later, from a
capture adapter. Keeping the model independent of the capture source is what
lets the same detectors run over lab traffic and (eventually) live traffic
without change.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

# Transport protocol numbers we care about (IANA assigned). Everything else is
# folded into ``OTHER`` so the feature vector stays fixed-width.
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# The ordered list of feature names the engine produces. Keeping this explicit
# (rather than inferring it) means alerts can name exactly which feature drove a
# score, which is what the GUI's "why" panel will render.
FEATURE_NAMES: tuple[str, ...] = (
    "log_bytes",          # log1p of total bytes transferred
    "log_packets",        # log1p of total packets
    "log_duration_ms",    # log1p of flow duration in milliseconds
    "log_bytes_per_packet",  # mean payload size (log), a traffic-type fingerprint
    "log_packets_per_sec",   # throughput (log); floods and scans sit at the extremes
    "dst_port_rank",      # 0..1 how "unusual" the destination port is
    "is_tcp",             # protocol one-hots
    "is_udp",
    "is_icmp",
    "syn_ratio",          # fraction of packets that are bare SYNs (scan tell)
)

# Ports that are ordinary server destinations. A destination *outside* this set
# is not itself suspicious, but the rank feature lets the model learn that most
# benign traffic clusters on a handful of well-known ports.
_COMMON_PORTS = frozenset(
    {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 465,
     587, 636, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443}
)


@dataclass(slots=True)
class FlowRecord:
    """A single bidirectional-ish flow summary.

    Fields mirror the NetFlow/IPFIX core set. Times are POSIX seconds (float).
    ``tcp_syns`` is the count of packets in the flow carrying only the SYN flag;
    it is cheap to collect from a capture and is a strong, honest signal for
    distinguishing a half-open scan from a completed connection.
    """

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    duration: float          # seconds
    packets: int
    bytes: int
    tcp_syns: int = 0
    label: str = "unknown"   # ground-truth tag from the lab; "unknown" in prod
    meta: dict = field(default_factory=dict)

    def features(self) -> np.ndarray:
        """Project the flow onto the fixed-width numeric feature vector.

        All heavy-tailed counts are log-compressed so a single elephant flow
        does not dominate the scale, and every value is finite (no NaN/inf) so
        downstream normalisation stays well-defined.
        """
        dur_ms = max(self.duration, 0.0) * 1000.0
        pkts = max(self.packets, 0)
        byts = max(self.bytes, 0)

        bytes_per_packet = byts / pkts if pkts else 0.0
        packets_per_sec = pkts / self.duration if self.duration > 1e-6 else float(pkts)
        syn_ratio = self.tcp_syns / pkts if pkts else 0.0

        # Destination-port "rank": 0 for the well-known ports, scaling toward 1
        # for high ephemeral/odd ports. This is a stable, source-free encoding.
        if self.dst_port in _COMMON_PORTS:
            dst_port_rank = 0.0
        else:
            dst_port_rank = min(self.dst_port, 65535) / 65535.0

        return np.array(
            [
                math.log1p(byts),
                math.log1p(pkts),
                math.log1p(dur_ms),
                # Log-compress the per-packet and rate features too: raw they are
                # heavy-tailed (benign rates span three orders of magnitude) and
                # would otherwise dominate any max-deviation statistic, masking
                # the feature an attack actually moves.
                math.log1p(bytes_per_packet),
                math.log1p(packets_per_sec),
                dst_port_rank,
                1.0 if self.proto == PROTO_TCP else 0.0,
                1.0 if self.proto == PROTO_UDP else 0.0,
                1.0 if self.proto == PROTO_ICMP else 0.0,
                syn_ratio,
            ],
            dtype=np.float64,
        )


def feature_dim() -> int:
    """Number of features each flow produces (stable across the codebase)."""
    return len(FEATURE_NAMES)
