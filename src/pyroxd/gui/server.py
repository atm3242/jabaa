"""pyroXD GUI backend -- a pure standard-library web server.

No web framework, no vendor runtime: the server is built on
``http.server.ThreadingHTTPServer`` so the only dependency remains numpy (for
the engine). It does three things:

* serves the hand-built front end (``static/``),
* exposes ``/api/meta`` with the engine's feature and detector names,
* streams live, explained alerts over **Server-Sent Events** at ``/api/stream``
  while running the :class:`~pyroxd.detect.ensemble.DetectionEngine` over the
  self-contained synthetic lab.

SSE is used instead of WebSockets precisely because it needs nothing beyond the
standard library: a long-lived HTTP response that writes ``data: {...}\\n\\n``
frames. The front end consumes it with the native ``EventSource`` API.

Run it with::

    python -m pyroxd serve           # then open http://127.0.0.1:8787
    python -m pyroxd serve --port 9000 --rate 25
"""

from __future__ import annotations

import json
import mimetypes
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..core.flow import FEATURE_NAMES
from ..detect.ensemble import DetectionEngine, EngineConfig
from ..lab.synth import labelled_scenario

_STATIC = Path(__file__).parent / "static"

# Human-readable detector descriptions surfaced in the GUI's legend/help.
_DETECTOR_INFO = {
    "half_space_trees": "Streaming Half-Space Trees - multivariate isolation",
    "ewma": "EWMA control chart - volumetric spikes",
    "entropy_dport": "Destination-port entropy - scan signature",
    "entropy_dstip": "Destination-IP entropy - fan-out / beacon signature",
}


def _flow_summary(flow) -> dict:
    return {
        "src": f"{flow.src_ip}:{flow.src_port}",
        "dst": f"{flow.dst_ip}:{flow.dst_port}",
        "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(flow.proto, str(flow.proto)),
        "bytes": flow.bytes,
        "packets": flow.packets,
    }


class _Handler(BaseHTTPRequestHandler):
    # Quieter logging; the CLI prints its own banner.
    def log_message(self, *args) -> None:  # noqa: D401
        pass

    # -------------------------------------------------------------- routing
    def do_GET(self) -> None:
        route = urlparse(self.path)
        if route.path == "/" or route.path == "/index.html":
            self._serve_static("index.html")
        elif route.path.startswith("/static/"):
            self._serve_static(route.path[len("/static/"):])
        elif route.path == "/api/meta":
            self._serve_json({
                "features": list(FEATURE_NAMES),
                "detectors": _DETECTOR_INFO,
            })
        elif route.path == "/api/stream":
            self._serve_stream(parse_qs(route.query))
        else:
            self.send_error(404, "not found")

    # -------------------------------------------------------------- helpers
    def _serve_static(self, rel: str) -> None:
        target = (_STATIC / rel).resolve()
        # Path-traversal guard: never serve outside the static root.
        if not str(target).startswith(str(_STATIC.resolve())) or not target.is_file():
            self.send_error(404, "not found")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_stream(self, qs: dict) -> None:
        """Run the engine over the lab and push one SSE frame per flow."""
        try:
            rate = float(qs.get("rate", ["20"])[0])      # flows per second
            seed = int(qs.get("seed", ["1"])[0])
            loop = qs.get("loop", ["1"])[0] != "0"
        except ValueError:
            self.send_error(400, "bad query")
            return
        delay = 1.0 / rate if rate > 0 else 0.0

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        try:
            while True:
                engine = DetectionEngine(EngineConfig(seed=7))
                for flow in labelled_scenario(seed=seed):
                    alert = engine.process(flow)
                    frame = {
                        "ts": alert.ts,
                        "score": round(alert.score, 4),
                        "is_anomaly": alert.is_anomaly,
                        "label": alert.label,
                        "contributions": {k: round(v, 4)
                                          for k, v in alert.contributions.items()},
                        "top_features": [[n, round(d, 2)] for n, d in alert.top_features],
                        "flow": _flow_summary(flow),
                        "telemetry": {k: (round(v, 4) if isinstance(v, float) else v)
                                     for k, v in engine.telemetry().items()},
                    }
                    payload = f"data: {json.dumps(frame)}\n\n".encode()
                    self.wfile.write(payload)
                    self.wfile.flush()
                    if delay:
                        time.sleep(delay)
                if not loop:
                    break
        except (BrokenPipeError, ConnectionResetError):
            return  # client navigated away; end the stream quietly


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"pyroXD GUI serving at {url}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
