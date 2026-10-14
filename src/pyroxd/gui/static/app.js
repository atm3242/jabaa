/* pyroXD console front end. Vanilla JS, no framework.
   Consumes the Server-Sent Events stream and renders four live views on
   hand-drawn canvases + animated DOM. */

"use strict";

const FAMILY_COLORS = {
  portscan: "#ffd43b", synflood: "#ff8787", exfil: "#ff4d5e",
  beacon: "#b197fc", benign: "#ffa94d", unknown: "#ffa94d",
};
const SAFE = [61, 220, 151], EMBER = [255, 107, 53], CRIT = [255, 77, 94];

const state = {
  threshold: 0.9,
  scores: [],            // ring buffer of {score, anomaly, label}
  maxPoints: 260,
  alerts: 0,
  entMax: { dport: 1, dstip: 1 },
  ent: { dport: 0, dstip: 0 },
  detectors: {},         // name -> latest contribution
};

/* ------------------------------------------------------------- utilities */
function lerp(a, b, t) { return a.map((x, i) => Math.round(x + (b[i] - x) * t)); }
function rgb(c) { return `rgb(${c[0]},${c[1]},${c[2]})`; }
function scoreColor(v) {
  return v < 0.5 ? lerp(SAFE, EMBER, v / 0.5) : lerp(EMBER, CRIT, (v - 0.5) / 0.5);
}
function fitCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const r = cv.getBoundingClientRect();
  cv.width = Math.max(1, r.width * dpr);
  cv.height = Math.max(1, r.height * dpr);
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: r.width, h: r.height };
}

/* ------------------------------------------------------------- bootstrap */
async function boot() {
  const meta = await fetch("/api/meta").then(r => r.json()).catch(() => null);
  const detBox = document.getElementById("detectors");
  const detInfo = (meta && meta.detectors) || {};
  const order = ["half_space_trees", "ewma", "entropy_dport", "entropy_dstip"];
  const pretty = { half_space_trees: "Half-Space Trees", ewma: "EWMA Control Chart",
    entropy_dport: "Dest-Port Entropy", entropy_dstip: "Dest-IP Entropy" };
  order.forEach(name => {
    const el = document.createElement("div");
    el.className = "detector";
    el.innerHTML = `
      <div class="row"><span class="name">${pretty[name] || name}</span><span class="val" id="dv-${name}">0.00</span></div>
      <div class="track"><div class="fill" id="df-${name}"></div></div>
      <div class="desc">${detInfo[name] || ""}</div>`;
    detBox.appendChild(el);
  });

  const legend = document.getElementById("legend");
  [["normal", rgb(SAFE)], ["suspicious", rgb(EMBER)], ["critical", rgb(CRIT)],
   ["port scan", FAMILY_COLORS.portscan], ["SYN flood", FAMILY_COLORS.synflood],
   ["exfiltration", FAMILY_COLORS.exfil], ["C2 beacon", FAMILY_COLORS.beacon]]
    .forEach(([t, c]) => {
      const s = document.createElement("span");
      s.innerHTML = `<i style="background:${c}"></i>${t}`;
      legend.appendChild(s);
    });

  wireHelp();
  connect();
  requestAnimationFrame(renderLoop);
}

/* --------------------------------------------------------------- stream */
function connect() {
  // Stream speed and scenario seed are URL-configurable, e.g. ?rate=120&seed=3.
  const q = new URLSearchParams(location.search);
  const rate = q.get("rate") || "22";
  const seed = q.get("seed") || "1";
  const es = new EventSource(`/api/stream?rate=${encodeURIComponent(rate)}&seed=${encodeURIComponent(seed)}&loop=1`);
  const pill = document.getElementById("livepill");
  const txt = document.getElementById("livetext");
  es.onopen = () => { txt.textContent = "streaming"; pill.classList.add("warm"); };
  es.onerror = () => { txt.textContent = "reconnecting"; pill.classList.remove("warm"); };
  es.onmessage = (ev) => {
    let f; try { f = JSON.parse(ev.data); } catch { return; }
    ingest(f);
  };
}

function ingest(f) {
  state.detectors = f.contributions;
  state.threshold = f.telemetry.threshold;
  state.ent.dport = f.telemetry.entropy_dport;
  state.ent.dstip = f.telemetry.entropy_dstip;
  state.entMax.dport = Math.max(state.entMax.dport, f.telemetry.entropy_dport);
  state.entMax.dstip = Math.max(state.entMax.dstip, f.telemetry.entropy_dstip);

  state.scores.push({ score: f.score, anomaly: f.is_anomaly, label: f.label });
  if (state.scores.length > state.maxPoints) state.scores.shift();

  document.getElementById("s-processed").textContent = f.telemetry.processed;
  document.getElementById("s-threshold").textContent = state.threshold.toFixed(2);
  if (f.telemetry.n_incidents != null)
    document.getElementById("s-incidents").textContent = f.telemetry.n_incidents;

  // Detector bars.
  for (const [name, v] of Object.entries(f.contributions)) {
    const fill = document.getElementById(`df-${name}`);
    const val = document.getElementById(`dv-${name}`);
    if (fill) { fill.style.width = (v * 100).toFixed(1) + "%"; }
    if (val) {
      val.textContent = v.toFixed(2);
      val.style.color = rgb(scoreColor(v));
    }
  }

  if (f.is_anomaly) { state.alerts++; document.getElementById("s-alerts").textContent = state.alerts; pushAlert(f); }
}

/* ---------------------------------------------------------- alert stream */
function pushAlert(f) {
  const box = document.getElementById("stream");
  const t = new Date(f.ts * 1000).toISOString().substr(11, 8);
  const col = FAMILY_COLORS[f.label] || FAMILY_COLORS.unknown;
  const drivers = Object.entries(f.contributions)
    .sort((a, b) => b[1] - a[1]).slice(0, 2)
    .map(([k, v]) => `${k.replace("entropy_", "H:").replace("half_space_trees", "HST")}=${v.toFixed(2)}`)
    .join("  ");
  const feats = f.top_features.map(([n, d]) => `${n} ${d.toFixed(1)}σ`).join(", ");

  const row = document.createElement("div");
  row.className = "stream-row new";
  row.innerHTML = `
    <span>${t}</span>
    <span class="score-cell">${f.score.toFixed(3)}</span>
    <span class="chip" style="color:${col}">${f.label}</span>
    <span class="drivers">${drivers}</span>`;
  row.title = `drivers: ${drivers}\nflow: ${f.flow.src} -> ${f.flow.dst} ${f.flow.proto}  ${f.flow.bytes}B / ${f.flow.packets}pkt\nfeatures: ${feats}`;
  row.addEventListener("click", () => {
    row.nextElementSibling && row.nextElementSibling.classList.contains("detail")
      ? row.nextElementSibling.remove()
      : row.insertAdjacentHTML("afterend",
        `<div class="stream-row detail" style="grid-template-columns:1fr;color:var(--ink-dim);cursor:default;background:rgba(255,107,53,0.04)">
           ${f.flow.src} → ${f.flow.dst} · ${f.flow.proto} · ${f.flow.bytes}B / ${f.flow.packets}pkt · drivers ${feats}</div>`);
  });
  box.prepend(row);
  while (box.children.length > 60) box.lastChild.remove();
}

/* -------------------------------------------------------- canvas render */
function renderLoop() {
  drawTimeline();
  drawGauge("g-dport", state.ent.dport, state.entMax.dport);
  drawGauge("g-dstip", state.ent.dstip, state.entMax.dstip);
  requestAnimationFrame(renderLoop);
}

function drawTimeline() {
  const cv = document.getElementById("timeline");
  const { ctx, w, h } = fitCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  const pad = 8, bottom = h - 6, top = pad;
  const plotH = bottom - top;
  const yOf = v => bottom - v * plotH;

  // horizontal guides
  ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.lineWidth = 1;
  for (let g = 0; g <= 1; g += 0.25) {
    ctx.beginPath(); ctx.moveTo(0, yOf(g)); ctx.lineTo(w, yOf(g)); ctx.stroke();
  }
  // threshold line
  ctx.setLineDash([5, 5]); ctx.strokeStyle = "rgba(255,169,77,0.6)";
  ctx.beginPath(); ctx.moveTo(0, yOf(state.threshold)); ctx.lineTo(w, yOf(state.threshold)); ctx.stroke();
  ctx.setLineDash([]);

  const n = state.scores.length;
  if (n < 2) return;
  const dx = w / (state.maxPoints - 1);
  const x0 = w - (n - 1) * dx;

  // area fill
  const grad = ctx.createLinearGradient(0, top, 0, bottom);
  grad.addColorStop(0, "rgba(255,107,53,0.30)");
  grad.addColorStop(1, "rgba(255,107,53,0.02)");
  ctx.beginPath(); ctx.moveTo(x0, bottom);
  state.scores.forEach((p, i) => ctx.lineTo(x0 + i * dx, yOf(p.score)));
  ctx.lineTo(x0 + (n - 1) * dx, bottom); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();

  // value line, coloured per segment by score
  ctx.lineWidth = 2; ctx.lineJoin = "round";
  for (let i = 1; i < n; i++) {
    ctx.beginPath();
    ctx.moveTo(x0 + (i - 1) * dx, yOf(state.scores[i - 1].score));
    ctx.lineTo(x0 + i * dx, yOf(state.scores[i].score));
    ctx.strokeStyle = rgb(scoreColor(state.scores[i].score));
    ctx.stroke();
  }
  // anomaly markers with glow
  state.scores.forEach((p, i) => {
    if (!p.anomaly) return;
    const x = x0 + i * dx, y = yOf(p.score);
    const c = FAMILY_COLORS[p.label] || FAMILY_COLORS.unknown;
    ctx.shadowColor = c; ctx.shadowBlur = 12;
    ctx.fillStyle = c; ctx.beginPath(); ctx.arc(x, y, 3.2, 0, 7); ctx.fill();
    ctx.shadowBlur = 0;
  });
}

function drawGauge(id, value, max) {
  const cv = document.getElementById(id);
  const ctx = cv.getContext("2d");
  const w = cv.width, h = cv.height;
  ctx.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h * 0.82, r = Math.min(w, h) * 0.62;
  const a0 = Math.PI, a1 = 2 * Math.PI;             // top semicircle
  const frac = max > 0 ? Math.min(value / max, 1) : 0;

  ctx.lineCap = "round";
  ctx.lineWidth = 14;
  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.beginPath(); ctx.arc(cx, cy, r, a0, a1); ctx.stroke();

  const col = scoreColor(frac);
  ctx.strokeStyle = rgb(col);
  ctx.shadowColor = rgb(col); ctx.shadowBlur = 14;
  ctx.beginPath(); ctx.arc(cx, cy, r, a0, a0 + (a1 - a0) * frac); ctx.stroke();
  ctx.shadowBlur = 0;

  ctx.fillStyle = "#e6e8ee"; ctx.textAlign = "center";
  ctx.font = "600 26px ui-monospace, monospace";
  ctx.fillText(value.toFixed(2), cx, cy - 6);
  ctx.fillStyle = "#5a5f6e"; ctx.font = "11px ui-monospace, monospace";
  ctx.fillText("bits", cx, cy + 14);
}

/* ---------------------------------------------------------------- help */
function wireHelp() {
  const ov = document.getElementById("overlay");
  document.getElementById("helpbtn").addEventListener("click", () => ov.classList.add("open"));
  document.getElementById("helpclose").addEventListener("click", () => ov.classList.remove("open"));
  ov.addEventListener("click", e => { if (e.target === ov) ov.classList.remove("open"); });
  document.addEventListener("keydown", e => { if (e.key === "Escape") ov.classList.remove("open"); });
}

boot();
