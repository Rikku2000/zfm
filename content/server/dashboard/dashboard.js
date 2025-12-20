const tableBody       = document.querySelector("#usersTable tbody");
const tgTableBody     = document.querySelector("#tgTable tbody");
const serverTimeEl    = document.getElementById("serverTime");
const statusMsgEl     = document.getElementById("statusMsg");
const weatherTgEl     = document.getElementById("weatherTg");
const clientCountEl   = document.getElementById("clientCount");
const activeSpeakerEl = document.getElementById("activeSpeaker");
const waveTgLabelEl   = document.getElementById("waveTgLabel");
const autoFollowEl    = document.getElementById("autoFollowTg");
const tgLinksEl       = document.getElementById("tgLinks");
const peersTableBody  = document.querySelector("#peersTable tbody");

const wfCanvas  = document.getElementById("wfCanvas");
const wfOverlay = document.getElementById("wfOverlay");
const wfCtx     = wfCanvas ? wfCanvas.getContext("2d") : null;
const ovCtx     = wfOverlay ? wfOverlay.getContext("2d") : null;

let currentWaveTg = "gateway";
let autoFollowTg = true;

if (autoFollowEl) {
  autoFollowTg = !!autoFollowEl.checked;
  autoFollowEl.addEventListener("change", () => {
    autoFollowTg = !!autoFollowEl.checked;
  });
}

async function fetchStatus() {
  try {
    const res = await fetch("/api/status", { cache: "no-store" });
    if (!res.ok) {
      throw new Error("HTTP " + res.status);
    }
    const data = await res.json();
    renderStatus(data);
    statusMsgEl.textContent = "Last update: " + new Date().toLocaleTimeString();
    statusMsgEl.style.color = "#aaaaaa";
  } catch (e) {
    statusMsgEl.textContent = "Error fetching status: " + e.message;
    statusMsgEl.style.color = "#ff5252";
  }
}

function renderStatus(data) {
  serverTimeEl.textContent = data.server_time_iso || "--";

  if (data.weather_talkgroup) {
    weatherTgEl.textContent = data.weather_talkgroup;
    weatherTgEl.style.color = "#4caf50";
  } else {
    weatherTgEl.textContent = "--";
    weatherTgEl.style.color = "#aaaaaa";
  }
  if (data.weather_rx_only) {
    weatherTgEl.textContent += " (RX Only)";
    weatherTgEl.style.color = "#ff5252";
  }

  if (typeof data.connected_clients === "number") {
    clientCountEl.textContent = data.connected_clients;
  } else {
    clientCountEl.textContent = "--";
  }

  const talkgroups = data.talkgroups || [];

  updateWaveformTgFromActivity(talkgroups);
  renderTalkgroups(talkgroups);

  renderTalkgroupLinks(talkgroups);
  renderPeers(data.peers || []);

  const entries = data.entries || [];
  renderUsers(entries);

  updateNowSpeaking(talkgroups);
}

function renderTalkgroups(tgs) {
  tgTableBody.innerHTML = "";

  if (!tgs || tgs.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.textContent = "No talkgroups.";
    td.style.textAlign = "center";
    td.style.color = "#777";
    tr.appendChild(td);
    tgTableBody.appendChild(tr);
    return;
  }

  for (const tg of tgs) {
    if (typeof tg.listeners === "number" && tg.listeners === 0)
      continue;

    if (!tg.name || tg.name === "-")
      continue;

    const tr = document.createElement("tr");
    tr.dataset.tgName = tg.name;

    if (tg.active_speaker) tr.classList.add("speaking");
    if (tg.name === currentWaveTg) tr.classList.add("selected");

    const activity = typeof tg.activity_score === "number" ? tg.activity_score : 0;

    if (activity > 0.66) tr.classList.add("heat-high");
    else if (activity > 0.33) tr.classList.add("heat-mid");
    else if (activity > 0.10) tr.classList.add("heat-low");

    const tdName = document.createElement("td");
    tdName.textContent = tg.name || "-";

    const tdSpeaker = document.createElement("td");
    tdSpeaker.textContent = tg.active_speaker || "-";

    const tdDur = document.createElement("td");
    if (tg.speak_ms && tg.speak_ms > 0) {
      const sec = tg.speak_ms / 1000;
      if (sec < 60) tdDur.textContent = sec.toFixed(1) + " s";
      else {
        const m = Math.floor(sec / 60);
        const s = Math.floor(sec % 60);
        tdDur.textContent = m + "m " + s + "s";
      }
    } else {
      tdDur.textContent = "-";
    }

    const tdListeners = document.createElement("td");
    tdListeners.textContent =
      typeof tg.listeners === "number" ? tg.listeners : "-";

    const tdLevel = document.createElement("td");
    const levelVal =
      typeof tg.audio_level === "number" ? tg.audio_level : 0;
    const levelOuter = document.createElement("div");
    levelOuter.className = "level-bar";
    const levelInner = document.createElement("div");
    levelInner.className = "level-bar-fill";
    levelInner.style.width = Math.round(levelVal * 100) + "%";
    levelOuter.appendChild(levelInner);
    tdLevel.appendChild(levelOuter);

    const tdActivity = document.createElement("td");
    if (activity > 0) {
      tdActivity.textContent = Math.round(activity * 100) + "%";
    } else {
      tdActivity.textContent = "-";
    }

    tr.append(tdName, tdSpeaker, tdDur, tdListeners, tdLevel, tdActivity);

    tr.addEventListener("click", () => {
      currentWaveTg = tg.name;
      waveTgLabelEl.textContent = currentWaveTg || "-";

      autoFollowTg = false;
      if (autoFollowEl) autoFollowEl.checked = false;
    });

    tgTableBody.appendChild(tr);
  }
}

function renderPeers(peers) {
  if (!peersTableBody) return;

  peersTableBody.innerHTML = "";

  if (!peers || peers.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "No peers configured.";
    td.style.textAlign = "center";
    td.style.color = "#777";
    tr.appendChild(td);
    peersTableBody.appendChild(tr);
    return;
  }

  for (const p of peers) {
    const tr = document.createElement("tr");

    const tdName = document.createElement("td");
    tdName.textContent = p.name || "-";

    const tdEndpoint = document.createElement("td");
    tdEndpoint.textContent = (p.host && p.port) ? `${p.host}:${p.port}` : "-";

    const tdStatus = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "badge dot " + (p.connected ? "ok" : "down");
    badge.textContent = p.connected ? "Online" : "Offline";
    tdStatus.appendChild(badge);

    const tdRules = document.createElement("td");
    tdRules.className = "peer-rules";
    if (Array.isArray(p.rules) && p.rules.length) tdRules.textContent = p.rules.join(", ");
    else tdRules.textContent = "-";

    tr.append(tdName, tdEndpoint, tdStatus, tdRules);
    peersTableBody.appendChild(tr);
  }
}

function renderTalkgroupLinks(tgs) {
  if (!tgLinksEl) return;
  tgLinksEl.innerHTML = "";

  if (!tgs || tgs.length === 0) {
    tgLinksEl.textContent = "No talkgroups.";
    tgLinksEl.style.color = "#777";
    return;
  }

  let any = false;
  for (const tg of tgs) {
    const linked = tg.linked || [];
    if (!linked.length) continue;
    any = true;

    const row = document.createElement("div");
    row.className = "tg-link-row";

    const strong = document.createElement("strong");
    strong.textContent = tg.name;
    row.appendChild(strong);

    const span = document.createElement("span");
    span.textContent = " <> " + linked.join(", ");
    row.appendChild(span);

    tgLinksEl.appendChild(row);
  }

  if (!any) {
    tgLinksEl.textContent = "No active talkgroup links (bridges).";
    tgLinksEl.style.color = "#777";
  } else {
    tgLinksEl.style.color = "";
  }
}

function renderUsers(entries) {
  tableBody.innerHTML = "";

  if (!entries || entries.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.textContent = "No users connected.";
    td.style.textAlign = "center";
    td.style.color = "#777";
    tr.appendChild(td);
    tableBody.appendChild(tr);
    return;
  }

  for (const e of entries) {
    const tr = document.createElement("tr");
    if (e.speaking) tr.classList.add("speaking");

    const tdUser = document.createElement("td");
    tdUser.textContent = e.callsign || "-";

    const tdTg = document.createElement("td");
    tdTg.textContent = e.talkgroup || "-";

    const tdSpeaking = document.createElement("td");
    const badge = document.createElement("span");
    badge.classList.add("badge", "dot");
    if (e.speaking) {
      badge.classList.add("speaking");
      badge.textContent = "Talking";
    } else {
      badge.classList.add("idle");
      badge.textContent = "Idle";
    }
    tdSpeaking.appendChild(badge);

    const tdDur = document.createElement("td");
    let ms = e.speak_ms || 0;
    if (e.speaking && ms > 0) {
      const sec = ms / 1000;
      if (sec < 60) tdDur.textContent = sec.toFixed(1) + " s";
      else {
        const m = Math.floor(sec / 60);
        const s = Math.floor(sec % 60);
        tdDur.textContent = m + "m " + s + "s";
      }
    } else {
      tdDur.textContent = "-";
    }

    const tdLevel = document.createElement("td");
    const levelVal =
      typeof e.audio_level === "number" ? e.audio_level : 0;
    const levelOuter = document.createElement("div");
    levelOuter.className = "level-bar";
    const levelInner = document.createElement("div");
    levelInner.className = "level-bar-fill";
    levelInner.style.width = Math.round(levelVal * 100) + "%";
    if (!e.speaking || levelVal <= 0) {
      levelInner.classList.add("level-bar-muted");
    }
    levelOuter.appendChild(levelInner);
    tdLevel.appendChild(levelOuter);

    tr.appendChild(tdUser);
    tr.appendChild(tdTg);
    tr.appendChild(tdSpeaking);
    tr.appendChild(tdDur);
    tr.appendChild(tdLevel);
    tableBody.appendChild(tr);
  }
}

function updateNowSpeaking(talkgroups) {
  if (!Array.isArray(talkgroups) || talkgroups.length === 0) {
    activeSpeakerEl.textContent = "";
    activeSpeakerEl.classList.remove("active");
    return;
  }

  const actives = talkgroups
    .filter(t => t && t.active_speaker && t.name && t.name !== "-")
    .map(t => ({ speaker: t.active_speaker, tg: t.name }));

  if (actives.length === 0) {
    activeSpeakerEl.textContent = "";
    activeSpeakerEl.classList.remove("active");
    return;
  }

  const wrap = document.createElement("div");
  wrap.className = "speaker-badges";

  for (const a of actives) {
    const badge = document.createElement("span");
    badge.className = "speaker-badge";
    badge.textContent = `${a.speaker} on ${a.tg}`;
    wrap.appendChild(badge);
  }

  activeSpeakerEl.innerHTML = "";
  activeSpeakerEl.appendChild(wrap);
  activeSpeakerEl.classList.add("active");
}

function updateWaveformTgFromActivity(talkgroups) {
  if (!autoFollowTg) return;
  if (!Array.isArray(talkgroups) || talkgroups.length === 0) return;

  const usable = talkgroups.filter(t => t && t.name && t.name !== "-" && (typeof t.listeners !== "number" || t.listeners > 0));
  if (!usable.length) return;

  let candidate = usable.find(t => t.active_speaker);
  if (!candidate) {
    candidate = usable
      .slice()
      .sort((a, b) => (b.activity_score || 0) - (a.activity_score || 0))[0];
  }

  if (!candidate || !candidate.name) return;

  const isSpeaking = !!candidate.active_speaker;
  const activity = typeof candidate.activity_score === "number" ? candidate.activity_score : 0;
  const shouldSwitch = isSpeaking || activity >= 0.12 || currentWaveTg === "gateway" || !currentWaveTg;

  if (shouldSwitch && candidate.name !== currentWaveTg) {
    currentWaveTg = candidate.name;
    if (waveTgLabelEl) waveTgLabelEl.textContent = currentWaveTg || "-";
  }
}

async function fetchWaveform(tg) {
  if (!tg) return;
  try {
    const res = await fetch(`/api/waveform?tg=${encodeURIComponent(tg)}`, { cache: "no-store" });
    if (!res.ok) return;
    const data = await res.json();
    const samples = data.samples || [];
    if (samples.length) {
      lastSamples = samples;
      lastSampleTs = performance.now();
    }
  } catch (_) {}
}

let dpr = 1;
let viewW = 0;
let viewH = 0;
let specH = 0;
let wfallH = 0;

let lastSamples = [];
let lastSampleTs = 0;
let lastMag = null;
let lastLineMag = null;

const FFT_N = 512;
const DISPLAY_BINS = 420;
const MIN_DB = -95;
const MAX_DB = -15;

const palette = (() => {
  const stops = [
    { t: 0.00, c: [  7,  20,  60] },
    { t: 0.18, c: [  0,  90, 160] },
    { t: 0.35, c: [  0, 180, 210] },
    { t: 0.55, c: [  0, 220, 120] },
    { t: 0.72, c: [ 240, 220,   0] },
    { t: 0.86, c: [ 255,  90,   0] },
    { t: 1.00, c: [ 255, 255, 255] },
  ];
  const out = new Uint8ClampedArray(256 * 3);
  for (let i = 0; i < 256; i++) {
    const t = i / 255;
    let a = stops[0], b = stops[stops.length - 1];
    for (let s = 0; s < stops.length - 1; s++) {
      if (t >= stops[s].t && t <= stops[s + 1].t) {
        a = stops[s];
        b = stops[s + 1];
        break;
      }
    }
    const u = (t - a.t) / Math.max(1e-9, (b.t - a.t));
    const r = Math.round(a.c[0] + (b.c[0] - a.c[0]) * u);
    const g = Math.round(a.c[1] + (b.c[1] - a.c[1]) * u);
    const bl = Math.round(a.c[2] + (b.c[2] - a.c[2]) * u);
    out[i * 3 + 0] = r;
    out[i * 3 + 1] = g;
    out[i * 3 + 2] = bl;
  }
  return out;
})();

function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }

function resizeWaterfallIfNeeded() {
  if (!wfCanvas || !wfOverlay || !wfCtx || !ovCtx) return;

  const rect = wfCanvas.getBoundingClientRect();
  const nextDpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  const nextW = Math.max(320, Math.floor(rect.width));
  const nextH = Math.max(180, Math.floor(rect.height));

  if (nextW === viewW && nextH === viewH && nextDpr === dpr) return;

  dpr = nextDpr;
  viewW = nextW;
  viewH = nextH;

  wfCanvas.width = Math.floor(viewW * dpr);
  wfCanvas.height = Math.floor(viewH * dpr);
  wfOverlay.width = Math.floor(viewW * dpr);
  wfOverlay.height = Math.floor(viewH * dpr);

  wfCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ovCtx.setTransform(dpr, 0, 0, dpr, 0, 0);

  specH = Math.round(viewH * 0.28);
  wfallH = viewH - specH - 1;

  wfCtx.fillStyle = "#0b0f14";
  wfCtx.fillRect(0, 0, viewW, viewH);
}

function fftMagDb(samples, n) {
  const re = new Float32Array(n);
  const im = new Float32Array(n);
  const len = samples.length;
  for (let i = 0; i < n; i++) {
    const x = i < len ? (samples[i] / 32768) : 0;
    const w = 0.5 - 0.5 * Math.cos((2 * Math.PI * i) / (n - 1));
    re[i] = x * w;
    im[i] = 0;
  }

  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      let tr = re[i]; re[i] = re[j]; re[j] = tr;
      let ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }

  for (let len2 = 2; len2 <= n; len2 <<= 1) {
    const ang = -2 * Math.PI / len2;
    const wlenR = Math.cos(ang);
    const wlenI = Math.sin(ang);
    for (let i = 0; i < n; i += len2) {
      let wr = 1, wi = 0;
      for (let j = 0; j < (len2 >> 1); j++) {
        const uR = re[i + j];
        const uI = im[i + j];
        const vR = re[i + j + (len2 >> 1)] * wr - im[i + j + (len2 >> 1)] * wi;
        const vI = re[i + j + (len2 >> 1)] * wi + im[i + j + (len2 >> 1)] * wr;
        re[i + j] = uR + vR;
        im[i + j] = uI + vI;
        re[i + j + (len2 >> 1)] = uR - vR;
        im[i + j + (len2 >> 1)] = uI - vI;
        const nwr = wr * wlenR - wi * wlenI;
        wi = wr * wlenI + wi * wlenR;
        wr = nwr;
      }
    }
  }

  const half = n >> 1;
  const mag = new Float32Array(half);
  for (let i = 0; i < half; i++) {
    const r = re[i];
    const ii = im[i];
    const m = Math.sqrt(r * r + ii * ii) / half;
    const db = 20 * Math.log10(m + 1e-12);
    mag[i] = db;
  }
  return mag;
}

function resampleBinsCentered(srcDb, outBins) {
  const n = srcDb.length;
  const out = new Float32Array(outBins);
  for (let x = 0; x < outBins; x++) {
    const t = x / (outBins - 1);
    const centered = (t - 0.5) * 2;
    const srcPos = centered < 0
      ? (n * 0.5) + (centered + 1) * (n * 0.5)
      : centered * (n * 0.5);

    const i0 = clamp(Math.floor(srcPos), 0, n - 1);
    const i1 = clamp(i0 + 1, 0, n - 1);
    const frac = srcPos - i0;
    out[x] = srcDb[i0] + (srcDb[i1] - srcDb[i0]) * frac;
  }
  return out;
}

function drawOverlays(lineMagDb) {
  if (!ovCtx) return;

  ovCtx.clearRect(0, 0, viewW, viewH);

  ovCtx.fillStyle = "rgba(11, 15, 20, 0.85)";
  ovCtx.fillRect(0, 0, viewW, specH);

  ovCtx.strokeStyle = "rgba(255,255,255,0.07)";
  ovCtx.lineWidth = 1;
  ovCtx.beginPath();
  const vLines = 10;
  for (let i = 0; i <= vLines; i++) {
    const x = Math.round((i / vLines) * viewW) + 0.5;
    ovCtx.moveTo(x, 0);
    ovCtx.lineTo(x, viewH);
  }
  const hLines = 6;
  for (let i = 0; i <= hLines; i++) {
    const y = Math.round((i / hLines) * viewH) + 0.5;
    ovCtx.moveTo(0, y);
    ovCtx.lineTo(viewW, y);
  }
  ovCtx.stroke();

  ovCtx.strokeStyle = "rgba(255, 82, 82, 0.85)";
  ovCtx.beginPath();
  ovCtx.moveTo(Math.round(viewW / 2) + 0.5, 0);
  ovCtx.lineTo(Math.round(viewW / 2) + 0.5, viewH);
  ovCtx.stroke();

  if (lineMagDb) {
    ovCtx.strokeStyle = "rgba(220, 235, 255, 0.95)";
    ovCtx.lineWidth = 1.5;
    ovCtx.beginPath();
    for (let x = 0; x < DISPLAY_BINS; x++) {
      const db = lineMagDb[x];
      const norm = (clamp(db, MIN_DB, MAX_DB) - MIN_DB) / (MAX_DB - MIN_DB);
      const y = specH - 3 - norm * (specH - 8);
      const px = (x / (DISPLAY_BINS - 1)) * viewW;
      if (x === 0) ovCtx.moveTo(px, y);
      else ovCtx.lineTo(px, y);
    }
    ovCtx.stroke();

    ovCtx.fillStyle = "rgba(150, 210, 255, 0.10)";
    ovCtx.lineTo(viewW, specH);
    ovCtx.lineTo(0, specH);
    ovCtx.closePath();
    ovCtx.fill();
  }

  ovCtx.strokeStyle = "rgba(255,255,255,0.12)";
  ovCtx.beginPath();
  ovCtx.moveTo(0, specH + 0.5);
  ovCtx.lineTo(viewW, specH + 0.5);
  ovCtx.stroke();

  ovCtx.fillStyle = "rgba(255,255,255,0.55)";
  ovCtx.font = "12px system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, sans-serif";
  ovCtx.textBaseline = "top";
  const labels = ["-0.5", "-0.25", "0", "+0.25", "+0.5"];
  for (let i = 0; i < labels.length; i++) {
    const x = (i / (labels.length - 1)) * viewW;
    const text = labels[i];
    const tw = ovCtx.measureText(text).width;
    ovCtx.fillText(text, clamp(x - tw / 2, 2, viewW - tw - 2), specH + 6);
  }
}

let scrollAcc = 0;
let lastFrameTs = 0;
function renderFrame(ts) {
  resizeWaterfallIfNeeded();
  if (!wfCtx || viewW === 0) {
    requestAnimationFrame(renderFrame);
    return;
  }

  const dt = lastFrameTs ? (ts - lastFrameTs) : 16;
  lastFrameTs = ts;

  scrollAcc += dt * 0.050;
  while (scrollAcc >= 1) {
    scrollAcc -= 1;

    const now = performance.now();
    const isLive = (now - lastSampleTs) < 650;

    if (isLive && lastSamples.length) {
      const magHalf = fftMagDb(lastSamples, FFT_N);
      lastMag = resampleBinsCentered(magHalf, DISPLAY_BINS);
    }

    if (!lastMag) {
      lastMag = new Float32Array(DISPLAY_BINS);
      for (let i = 0; i < DISPLAY_BINS; i++) lastMag[i] = -80;
    }

    const lineMag = new Float32Array(DISPLAY_BINS);
    const t = ts * 0.001;
    for (let i = 0; i < DISPLAY_BINS; i++) {
      const base = lastMag[i];
      const noise = (Math.random() - 0.5) * 6.0;
      const ripple = Math.sin(t * 0.7 + i * 0.018) * 2.0;
      const target = isLive ? base : (-78 + ripple + noise);
      const prev = lastLineMag ? lastLineMag[i] : target;
      lineMag[i] = prev + (target - prev) * (isLive ? 0.55 : 0.12);
    }
    lastLineMag = lineMag;

    wfCtx.drawImage(
      wfCanvas,
      0, specH + 1, viewW, wfallH - 1,
      0, specH + 2, viewW, wfallH - 1
    );

    const img = wfCtx.createImageData(viewW, 1);
    for (let x = 0; x < viewW; x++) {
      const bin = Math.floor((x / (viewW - 1)) * (DISPLAY_BINS - 1));
      const db = lineMag[bin];
      const norm = (clamp(db, MIN_DB, MAX_DB) - MIN_DB) / (MAX_DB - MIN_DB);
      const p = clamp(Math.floor(norm * 255), 0, 255);
      const r = palette[p * 3 + 0];
      const g = palette[p * 3 + 1];
      const b = palette[p * 3 + 2];
      const i4 = x * 4;
      img.data[i4 + 0] = r;
      img.data[i4 + 1] = g;
      img.data[i4 + 2] = b;
      img.data[i4 + 3] = 255;
    }
    wfCtx.putImageData(img, 0, specH + 1);

    wfCtx.fillStyle = "#0b0f14";
    wfCtx.fillRect(0, 0, viewW, specH);

    drawOverlays(lineMag);
  }

  requestAnimationFrame(renderFrame);
}

fetchStatus();
setInterval(fetchStatus, 1000);

setInterval(() => {
  fetchWaveform(currentWaveTg);
  waveTgLabelEl.textContent = currentWaveTg || "-";
}, 200);

requestAnimationFrame(renderFrame);
