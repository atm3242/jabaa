"""Synthetic, fully self-contained traffic generator for the pyroXD lab.

This module fabricates :class:`~pyroxd.core.flow.FlowRecord` streams in memory.
It never opens a socket, sends a packet, or touches a real host -- it exists so
the detection engine can be trained and validated against *labelled* traffic in
a controlled setting, which is the only way to measure precision/recall on an
unsupervised detector.

The benign model is a mixture of a few realistic server conversations (web,
DNS, SSH, mail). Attack episodes are injected as labelled bursts whose
*statistical signature* matches the real thing, so the engine learns to catch
the pattern -- not a magic flag:

* ``portscan``   -- one source, one destination, many destination ports, tiny
                    half-open (SYN-only) flows. Signature: destination-port
                    entropy collapse + high SYN ratio.
* ``synflood``   -- many sources, one destination/port, high packet rate, tiny
                    flows. Signature: source fan-in + rate blowout.
* ``exfil``      -- a single, enormously large outbound flow. Signature: bytes
                    and bytes/packet many sigma above baseline.
* ``beacon``     -- periodic small flows to one external destination (C2-style
                    heartbeat). Signature: low-entropy, regular cadence.

These are detection *targets*, generated as data. Nothing here is weaponised or
aimed at a real system.
"""

from __future__ import annotations

import numpy as np

from ..core.flow import PROTO_TCP, PROTO_UDP, FlowRecord

_BENIGN_SERVERS = [
    # (dst_ip, dst_port, proto, mean_bytes, mean_pkts, mean_dur)
    ("10.0.0.10", 443, PROTO_TCP, 45000, 60, 1.2),
    ("10.0.0.10", 80, PROTO_TCP, 12000, 20, 0.6),
    ("10.0.0.20", 53, PROTO_UDP, 180, 2, 0.02),
    ("10.0.0.30", 22, PROTO_TCP, 8000, 40, 8.0),
    ("10.0.0.40", 25, PROTO_TCP, 15000, 25, 2.0),
]


class SyntheticTraffic:
    """Generate benign background flows and labelled attack episodes."""

    def __init__(self, seed: int | None = 1) -> None:
        self._rng = np.random.default_rng(seed)
        self._t = 1_700_000_000.0  # arbitrary fixed POSIX epoch start

    def _advance(self, dt: float = 0.05) -> float:
        self._t += dt
        return self._t

    def benign_flow(self) -> FlowRecord:
        """One realistic background flow drawn from the server mixture."""
        i = int(self._rng.integers(len(_BENIGN_SERVERS)))
        dst_ip, dport, proto, mb, mp, md = _BENIGN_SERVERS[i]
        # Log-normal spread keeps values positive and heavy-tailed like real traffic.
        byts = int(max(1, self._rng.lognormal(np.log(mb), 0.4)))
        pkts = int(max(1, self._rng.lognormal(np.log(mp), 0.3)))
        dur = float(max(0.001, self._rng.lognormal(np.log(md), 0.3)))
        src = f"192.168.1.{int(self._rng.integers(2, 200))}"
        sport = int(self._rng.integers(1024, 65535))
        syns = 1 if proto == PROTO_TCP else 0
        return FlowRecord(
            ts=self._advance(), src_ip=src, dst_ip=dst_ip, src_port=sport,
            dst_port=dport, proto=proto, duration=dur, packets=pkts,
            bytes=byts, tcp_syns=syns, label="benign",
        )

    def benign_stream(self, n: int):
        for _ in range(n):
            yield self.benign_flow()

    # ---------------------------------------------------------------- attacks
    def portscan(self, n_ports: int = 60, src: str = "192.168.1.66",
                 target: str = "10.0.0.10"):
        """One host sweeping many destination ports with SYN-only probes."""
        for _ in range(n_ports):
            port = int(self._rng.integers(1, 65535))
            yield FlowRecord(
                ts=self._advance(0.01), src_ip=src, dst_ip=target,
                src_port=int(self._rng.integers(40000, 65535)), dst_port=port,
                proto=PROTO_TCP, duration=0.001,
                packets=1, bytes=40, tcp_syns=1, label="portscan",
            )

    def synflood(self, n: int = 120, target: str = "10.0.0.10",
                 dport: int = 80):
        """Many spoofed-looking sources hammering one service, tiny fast flows."""
        for _ in range(n):
            src = f"172.16.{int(self._rng.integers(0, 255))}.{int(self._rng.integers(1, 255))}"
            yield FlowRecord(
                ts=self._advance(0.002), src_ip=src, dst_ip=target,
                src_port=int(self._rng.integers(1024, 65535)), dst_port=dport,
                proto=PROTO_TCP, duration=0.0005,
                packets=1, bytes=60, tcp_syns=1, label="synflood",
            )

    def exfil(self, target: str = "203.0.113.5"):
        """A single, abnormally large outbound transfer."""
        byts = int(self._rng.lognormal(np.log(50_000_000), 0.2))  # ~50 MB
        yield FlowRecord(
            ts=self._advance(0.5), src_ip="192.168.1.50", dst_ip=target,
            src_port=int(self._rng.integers(1024, 65535)), dst_port=443,
            proto=PROTO_TCP, duration=30.0, packets=40000, bytes=byts,
            tcp_syns=1, label="exfil",
        )

    def beacon(self, n: int = 20, target: str = "203.0.113.9"):
        """Periodic small heartbeat flows to one external host (C2 cadence)."""
        for _ in range(n):
            yield FlowRecord(
                ts=self._advance(5.0), src_ip="192.168.1.77", dst_ip=target,
                src_port=int(self._rng.integers(1024, 65535)), dst_port=8443,
                proto=PROTO_TCP, duration=0.2, packets=6, bytes=512,
                tcp_syns=1, label="beacon",
            )


def labelled_scenario(seed: int | None = 1) -> list[FlowRecord]:
    """Build a reproducible mixed stream: benign warmup, then injected attacks.

    Returns a flat, time-ordered list so tests can measure detection quality.
    The long benign prefix lets the unsupervised detectors establish a baseline
    before any attack appears -- exactly how they would run in production.
    """
    gen = SyntheticTraffic(seed=seed)
    flows: list[FlowRecord] = []
    # 1500-flow benign baseline so HST closes several reference windows.
    flows.extend(gen.benign_stream(1500))
    # Interleave attacks with benign cover traffic.
    flows.extend(gen.portscan())
    flows.extend(gen.benign_stream(100))
    flows.extend(gen.synflood())
    flows.extend(gen.benign_stream(100))
    flows.extend(gen.exfil())
    flows.extend(gen.benign_stream(100))
    flows.extend(gen.beacon())
    flows.extend(gen.benign_stream(100))
    return flows
