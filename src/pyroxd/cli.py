"""Command-line entry point for the pyroXD engine.

Provides a runnable demonstration of the real-time detection engine over the
self-contained synthetic lab, with a live, explained alert feed. This is the
text-mode counterpart of the GUI live view planned for the next milestone, and
it is what the GUI backend will drive internally.

Usage::

    python -m pyroxd demo            # run the built-in labelled scenario
    python -m pyroxd demo --seed 3   # a different reproducible scenario
"""

from __future__ import annotations

import argparse
import sys

from .detect.ensemble import DetectionEngine, EngineConfig
from .lab.synth import labelled_scenario

ATTACK_LABELS = {"portscan", "synflood", "exfil", "beacon"}

# ANSI colours; degrade gracefully if stdout is not a TTY.
_C = {
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}


def _paint(s: str, colour: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"{_C[colour]}{s}{_C['reset']}"


def cmd_demo(args: argparse.Namespace) -> int:
    flows = labelled_scenario(seed=args.seed)
    engine = DetectionEngine(EngineConfig(seed=7))

    print(_paint("pyroXD :: real-time anomaly detection demo", "bold"))
    print(_paint(f"processing {len(flows)} flows from the synthetic lab "
                 f"(seed={args.seed})\n", "dim"))

    n_alerts = tp = fp = 0
    for f in flows:
        a = engine.process(f)
        if not a.is_anomaly:
            continue
        n_alerts += 1
        is_attack = a.label in ATTACK_LABELS
        tp += is_attack
        fp += not is_attack
        tag = _paint(f"{a.label:9s}", "red" if is_attack else "yellow")
        why = ", ".join(f"{k}={v:.2f}" for k, v in sorted(
            a.contributions.items(), key=lambda kv: -kv[1])[:2])
        feats = ", ".join(f"{n}:{d:.1f}sigma" for n, d in a.top_features[:2])
        print(f"  [{a.ts:.2f}] score={_paint(f'{a.score:.3f}','bold')} "
              f"{tag} | {why} | drivers: {feats}")

    print()
    print(_paint(f"{n_alerts} alerts  |  {tp} on attack flows  |  "
                 f"{fp} on benign flows", "green"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pyroxd", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo", help="run the built-in detection demo")
    d.add_argument("--seed", type=int, default=1, help="scenario RNG seed")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("serve", help="launch the pyroXD web GUI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_serve)

    e = sub.add_parser("eval", help="benchmark the engine across seeds")
    e.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    e.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    e.set_defaults(func=cmd_eval)

    args = parser.parse_args(argv)
    return args.func(args)


def cmd_eval(args: argparse.Namespace) -> int:
    import json as _json
    from .eval.benchmark import format_report, run_benchmark
    result = run_benchmark(seeds=tuple(args.seeds))
    print(format_report(result))
    if args.json:
        with open(args.json, "w") as fh:
            _json.dump(result, fh, indent=2)
        print(f"\nfull report written to {args.json}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .gui.server import serve
    serve(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
