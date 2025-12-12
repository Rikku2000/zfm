const tableBody       = document.querySelector("#usersTable tbody");
const tgTableBody     = document.querySelector("#tgTable tbody");
const serverTimeEl    = document.getElementById("serverTime");
const statusMsgEl     = document.getElementById("statusMsg");
const weatherTgEl     = document.getElementById("weatherTg");
const clientCountEl   = document.getElementById("clientCount");
const activeSpeakerEl = document.getElementById("activeSpeaker");
const waveTgLabelEl   = document.getElementById("waveTgLabel");
const tgLinksEl       = document.getElementById("tgLinks");
const peersTableBody  = document.querySelector("#peersTable tbody");

const waveCanvas = document.getElementById("waveCanvas");
const waveCtx    = waveCanvas.getContext("2d");

let currentWaveTg = "gateway";

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
  renderTalkgroups(talkgroups);

  renderTalkgroupLinks(talkgroups);
  renderPeers(data.peers || []);

  const entries = data.entries || [];
  renderUsers(entries);

  updateNowSpeaking(talkgroups);

  autoSelectWaveformTg(talkgroups);
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

function autoSelectWaveformTg(talkgroups) {
  if (!talkgroups || talkgroups.length === 0) return;

  if (!currentWaveTg || currentWaveTg === "gateway") {
	const active = talkgroups.find(t => t.active_speaker && t.name && t.name !== "-");
    if (active) {
      currentWaveTg = active.name;
    } else {
      currentWaveTg = talkgroups[0].name;
	  if (!currentWaveTg || currentWaveTg === "-")
		return;
    }
    waveTgLabelEl.textContent = currentWaveTg || "-";
  }
}

async function fetchWaveform(tg) {
  if (!tg) return;
  try {
    const res = await fetch(`/api/waveform?tg=${encodeURIComponent(tg)}`, {
      cache: "no-store",
    });
    if (!res.ok) return;
    const data = await res.json();
    const samples = data.samples || [];
    drawWaveform(samples);
  } catch (_) {
  }
}

function drawWaveform(samples) {
  const w = waveCanvas.width;
  const h = waveCanvas.height;

  waveCtx.fillStyle = "#101010";
  waveCtx.fillRect(0, 0, w, h);

  if (!samples || samples.length === 0) return;

  waveCtx.strokeStyle = "#ff5252";
  waveCtx.lineWidth = 2;

  waveCtx.beginPath();
  for (let i = 0; i < samples.length; i++) {
    const x = (i / (samples.length - 1)) * w;
    const y = h / 2 - (samples[i] / 32768) * (h / 2);
    if (i === 0) waveCtx.moveTo(x, y);
    else waveCtx.lineTo(x, y);
  }
  waveCtx.stroke();
}

fetchStatus();
setInterval(fetchStatus, 1000);

setInterval(() => {
  fetchWaveform(currentWaveTg);
  waveTgLabelEl.textContent = currentWaveTg || "-";
}, 200);
