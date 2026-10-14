# Safety and Containment Model

pyroXD is a security *learning and detection* platform. "Safe and secure by
default" is a design constraint, not a feature we add later. This document
states the boundaries plainly.

## 1. The lab is self-contained

The synthetic lab (`pyroxd.lab.synth`) **fabricates traffic in memory**. It:

- never opens a network socket,
- never sends a packet to any host,
- never scans, probes, or connects to anything,
- produces `FlowRecord` objects — plain data structures — only.

The "attacks" it generates (port scan, SYN flood, exfiltration, C2 beacon) are
*statistical signatures rendered as labelled data*, so the detection engine can
be trained and measured against known ground truth. They are **detection
targets, not weapons**. There is no exploit code, no payload delivery, and no
capability to act against a real system anywhere in this repository.

## 2. Why containment is also correct engineering

Generating attack-shaped *data* in a controlled, labelled setting is the only
way to measure an unsupervised detector's precision and recall. Containment and
scientific rigour point the same direction: you cannot compute recall without
ground-truth labels, and you get trustworthy labels by generating the traffic
yourself, in memory, where nothing can escape.

## 3. The engine is read-only and non-destructive

The `DetectionEngine` **observes and scores**. It raises alerts; it does not
block, quarantine, reset connections, or modify any system. Automated response
(mitigation) is deliberately out of milestone 1. When mitigation is introduced,
it will be:

- **opt-in and off by default**, never automatic on first run;
- **confined to the lab** unless an operator explicitly authorises a specific,
  scoped action on a system they own;
- **auditable**, with every action logged.

## 4. Future live-capture guardrails (roadmap)

When a live-capture adapter is added, it will be built with these constraints:

- capture is **passive** (observe only); pyroXD never injects traffic;
- it requires an explicit, per-session operator opt-in and names the interface
  it will read;
- it is isolated behind the flow-source boundary so it cannot reach into the
  engine's logic or the OS beyond reading frames.

## 5. Responsible-use expectation

pyroXD is intended for use on systems and networks you own or are explicitly
authorised to test — a classroom lab, a research testbed, your own
infrastructure. It is a defensive and educational instrument. Using any
security tool against systems without authorisation is unlawful in most
jurisdictions and is outside the purpose of this project.

## 6. Secure-by-default checklist (current state)

- [x] No outbound network calls from pyroXD itself.
- [x] No third-party vendor, license key, or external AI service.
- [x] Lab traffic is fabricated in memory; no sockets.
- [x] Engine is observe-only; no destructive actions.
- [x] Dependencies are minimal and permissively licensed (see `TOOLS.md`).
- [ ] Automated mitigation — not yet implemented; will be opt-in and audited.
- [ ] Live capture — not yet implemented; will be passive and opt-in.
