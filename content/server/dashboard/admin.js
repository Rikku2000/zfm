const adminTitle  = document.getElementById("adminTitle");
const adminMenu  = document.getElementById("adminMenu");
const loginCard  = document.getElementById("loginCard");
const adminCard  = document.getElementById("adminCard");
const loginBtn   = document.getElementById("loginBtn");
const logoutBtn  = document.getElementById("logoutBtn");
const refreshBtn = document.getElementById("refreshBtn");
const loginMsg   = document.getElementById("loginMsg");
const adminMsg   = document.getElementById("adminMsg");
const tabContent = document.getElementById("tabContent");

const csEl = document.getElementById("loginCallsign");
const pwEl = document.getElementById("loginPassword");

let token = localStorage.getItem("zfm_admin_token") || "";
let me = null;
let cfg = null;

const menuBtn = document.getElementById("menuBtn");
const drawer = document.getElementById("drawer");
const drawerOverlay = document.getElementById("drawerOverlay");
const drawerCloseBtn = document.getElementById("drawerCloseBtn");

const modalOverlay = document.getElementById("modalOverlay");
const modalTitleEl = document.getElementById("modalTitle");
const modalBodyEl = document.getElementById("modalBody");
const modalMsgEl = document.getElementById("modalMsg");
const modalSaveBtn = document.getElementById("modalSaveBtn");
const modalCancelBtn = document.getElementById("modalCancelBtn");
const modalCloseBtn = document.getElementById("modalCloseBtn");

let modalOnSave = null;

const DRAWER_DUR_MS = 260;
const MODAL_DUR_MS = 200;

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    if (t) clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function openDrawer() {
  if (!drawer || !drawerOverlay) return;
  drawer.classList.remove("hidden");
  drawerOverlay.classList.remove("hidden");
  requestAnimationFrame(() => {
    drawer.classList.add("open");
    drawerOverlay.classList.add("open");
  });
}

function closeDrawer() {
  if (!drawer || !drawerOverlay) return;
  drawer.classList.remove("open");
  drawerOverlay.classList.remove("open");
  setTimeout(() => {
    drawer.classList.add("hidden");
    drawerOverlay.classList.add("hidden");
  }, DRAWER_DUR_MS);
}

function openModal(title, bodyHtml, onSave) {
  modalTitleEl.textContent = title || "Edit";
  modalBodyEl.innerHTML = bodyHtml || "";
  modalMsgEl.textContent = "";
  modalOnSave = onSave || null;
  modalOverlay.classList.remove("hidden");
  requestAnimationFrame(() => modalOverlay.classList.add("open"));
}

function closeModal() {
  modalOverlay.classList.remove("open");
  setTimeout(() => modalOverlay.classList.add("hidden"), MODAL_DUR_MS);
  modalOnSave = null;
}

async function saveModal() {
  if (!modalOnSave) return closeModal();
  try {
    modalSaveBtn.disabled = true;
    await modalOnSave();
    closeModal();
  } catch (e) {
    modalMsgEl.textContent = e.message || String(e);
    modalMsgEl.style.color = "#ff5252";
  } finally {
    modalSaveBtn.disabled = false;
  }
}

function v(id) {
  const el = modalBodyEl.querySelector("#" + id);
  return el ? el.value : "";
}

function csvToArr(s) {
  return (s || "").split(",").map(x => x.trim()).filter(Boolean);
}

function arrToCsv(a) {
  return Array.isArray(a) ? a.join(",") : "";
}

function openUserModal(u) {
  const isNew = !u;
  const data = u || { callsign: "", password: "", role: "user", banned: false, priority: 0, talkgroups: [], permissions: [] };
  openModal(isNew ? "Add user" : `Edit user ${data.callsign}`, `
    <div class="grid2">
      <div class="form-row">
        <label>Callsign</label>
        <input id="m_user_callsign" ${isNew ? "" : "disabled"} value="${esc(data.callsign)}" placeholder="NEW1" />
      </div>
      <div class="form-row">
        <label>Role</label>
        <select id="m_user_role">
          <option value="user" ${data.role==="user"?"selected":""}>user</option>
          <option value="operator" ${data.role==="operator"?"selected":""}>operator</option>
          <option value="admin" ${data.role==="admin"?"selected":""}>admin</option>
        </select>
      </div>
      <div class="form-row">
        <label>Password</label>
        <input id="m_user_password" value="${esc(data.password || "")}" placeholder="secret" />
      </div>
      <div class="form-row">
        <label>Priority</label>
        <input id="m_user_priority" value="${esc(data.priority ?? 0)}" inputmode="numeric" />
      </div>
      <div class="form-row">
        <label>Banned</label>
        <select id="m_user_banned">
          <option value="false" ${data.banned ? "" : "selected"}>false</option>
          <option value="true" ${data.banned ? "selected" : ""}>true</option>
        </select>
      </div>
      <div class="form-row">
        <label>Talkgroups (csv)</label>
        <input id="m_user_tgs" value="${esc(arrToCsv(data.talkgroups))}" placeholder="tg1,tg2" />
      </div>
      <div class="form-row" style="grid-column: 1 / -1;">
        <label>Permissions (csv)</label>
        <input id="m_user_perms" value="${esc(arrToCsv(data.permissions))}" placeholder="config.read,users.write" />
      </div>
    </div>
  `, async () => {
    const callsign = isNew ? v("m_user_callsign").trim() : data.callsign;
    if (!callsign) throw new Error("Callsign is required.");
    const body = {
      callsign,
      role: v("m_user_role").trim() || "user",
      password: v("m_user_password"),
      priority: Number(v("m_user_priority") || 0),
      banned: v("m_user_banned") === "true",
      talkgroups: csvToArr(v("m_user_tgs")),
      permissions: csvToArr(v("m_user_perms")),
    };
    await api("/api/admin/users", { method: "POST", body });
    setMsg(adminMsg, isNew ? `Created ${callsign}.` : `Saved ${callsign}.`);
    await refreshAll();
    activeTab = "users";
    renderUsers();
  });
}

function openTalkgroupModal(t) {
  const isNew = !t;
  const data = t || { name: "", mode: "public" };
  openModal(isNew ? "Add talkgroup" : `Edit talkgroup ${data.name}`, `
    <div class="grid2">
      <div class="form-row">
        <label>Name</label>
        <input id="m_tg_name" ${isNew ? "" : "disabled"} value="${esc(data.name)}" placeholder="TG1" />
      </div>
      <div class="form-row">
        <label>Mode</label>
        <select id="m_tg_mode">
          <option value="public" ${data.mode==="public"?"selected":""}>public</option>
          <option value="hide" ${data.mode==="hide"?"selected":""}>hide</option>
          <option value="admin" ${data.mode==="admin"?"selected":""}>admin</option>
        </select>
      </div>
    </div>
  `, async () => {
    const name = isNew ? v("m_tg_name").trim() : data.name;
    if (!name) throw new Error("Name is required.");
    const body = { name, mode: v("m_tg_mode") || "public" };
    await api("/api/admin/talkgroups", { method: "POST", body });
    setMsg(adminMsg, isNew ? `Created ${name}.` : `Saved ${name}.`);
    await refreshAll();
    activeTab = "talkgroups";
    renderTalkgroups();
  });
}

function openBridgeModal(b) {
  const isNew = !b;
  const data = b || { talkgroup: "", linked: [] };

  openModal(isNew ? "Add bridge" : `Edit bridge ${data.talkgroup}`, `
    <div class="grid2">
      <div class="form-row">
        <label>Talkgroup</label>
        <input id="m_bridge_tg" ${isNew ? "" : "disabled"} value="${esc(data.talkgroup)}" />
      </div>
      <div class="form-row">
        <label>Linked (csv)</label>
        <input id="m_bridge_linked" value="${esc(arrToCsv(data.linked))}" placeholder="tgA,tgB" />
      </div>
    </div>
  `, async () => {
    const talkgroup = isNew ? v("m_bridge_tg").trim() : data.talkgroup;
    if (!talkgroup) throw new Error("Talkgroup is required.");

    const linked = csvToArr(v("m_bridge_linked"));

    await api("/api/admin/bridges", { method: "POST", body: { talkgroup, linked } });
    setMsg(adminMsg, isNew ? `Created bridge ${talkgroup}.` : `Saved bridge ${talkgroup}.`);
    await refreshAll();
    activeTab = "bridges";
    renderBridges();
  });
}

function openPeerModal(p) {
  const isNew = !p;
  const data = p || { name: "", host: "", port: "", secret: "", rules: [] };

  openModal(isNew ? "Add peer" : `Edit peer ${data.name}`, `
    <div class="grid2">
      <div class="form-row">
        <label>Name</label>
        <input id="m_peer_name" ${isNew ? "" : "disabled"} value="${esc(data.name)}" />
      </div>
      <div class="form-row">
        <label>Host</label>
        <input id="m_peer_host" value="${esc(data.host)}" />
      </div>
      <div class="form-row">
        <label>Port</label>
        <input id="m_peer_port" value="${esc(data.port)}" />
      </div>
      <div class="form-row">
        <label>Secret</label>
        <input id="m_peer_secret" value="${esc(data.secret || "")}" />
      </div>
      <div class="form-row" style="grid-column: 1 / -1;">
        <label>Rules (csv)</label>
        <input id="m_peer_rules" value="${esc(arrToCsv(data.rules))}" />
      </div>
    </div>
  `, async () => {
    const name = isNew ? v("m_peer_name").trim() : data.name;
    if (!name) throw new Error("Name is required.");

    await api("/api/admin/peers", {
      method: "POST",
      body: {
        op: "upsert",
        name,
        host: v("m_peer_host").trim(),
        port: parseInt(v("m_peer_port"), 10),
        secret: v("m_peer_secret"),
        rules: csvToArr(v("m_peer_rules"))
      }
    });

    setMsg(adminMsg, isNew ? `Created peer ${name}.` : `Saved peer ${name}.`);
    await refreshAll();
    activeTab = "peers";
    renderPeers();
  });
}

let activeTab = "users";

function setMsg(el, text, ok = true) {
  el.textContent = text;
  el.style.color = ok ? "#aaaaaa" : "#ff5252";
}

async function api(path, { method = "GET", body = null } = {}) {
  const headers = {};
  if (token) headers["Authorization"] = "Bearer " + token;
  if (body !== null) headers["Content-Type"] = "application/json";

  const res = await fetch(path, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : null,
    cache: "no-store",
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (_) {}

  if (!res.ok) {
    const msg = (data && data.error) ? data.error : (text || ("HTTP " + res.status));
    throw new Error(msg);
  }
  return data;
}

function showLogin() {
  loginCard.classList.remove("hidden");
  adminTitle.classList.remove("hidden");
  adminMenu.classList.add("hidden");
  adminCard.classList.add("hidden");
  logoutBtn.disabled = true;
}

function showAdmin() {
  loginCard.classList.add("hidden");
  adminTitle.classList.add("hidden");
  adminMenu.classList.remove("hidden");
  adminCard.classList.remove("hidden");
  logoutBtn.disabled = false;
}

async function doLogin() {
  try {
    setMsg(loginMsg, "Logging in…");
    const r = await api("/api/login", {
      method: "POST",
      body: { callsign: csEl.value.trim(), password: pwEl.value },
    });
    token = r.token;
    localStorage.setItem("zfm_admin_token", token);
    me = r;
    await refreshAll();
    setMsg(adminMsg, "Logged in.");
  } catch (e) {
    token = "";
    localStorage.removeItem("zfm_admin_token");
    showLogin();
    setMsg(loginMsg, "Login failed: " + e.message, false);
  }
}

async function doLogout() {
  try { if (token) await api("/api/logout", { method: "POST" }); } catch (_) {}
  token = "";
  me = null;
  cfg = null;
  localStorage.removeItem("zfm_admin_token");
  showLogin();
  setMsg(loginMsg, "Logged out.");
}

async function refreshAll() {
  try {
    cfg = await api("/api/admin/config");
    showAdmin();
    const role = (me && me.role) ? me.role : "?";
    renderTab(activeTab);
  } catch (e) {
    showLogin();
    setMsg(loginMsg, "Cannot load admin config: " + e.message, false);
  }
}

function tabsInit() {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeTab = btn.dataset.tab;
      renderTab(activeTab);
    });
  });
}

function esc(s) {
  return (s ?? "").toString().replace(/[&<>\"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

function renderTab(tab) {
  if (!cfg) {
    tabContent.innerHTML = "<div class=\"status-msg\">No config loaded.</div>";
    return;
  }
  setMsg(adminMsg, "");
  if (tab === "users") return renderUsers();
  if (tab === "talkgroups") return renderTalkgroups();
  if (tab === "bridges") return renderBridges();
  if (tab === "peers") return renderPeers();
  if (tab === "time") return renderTime();
  if (tab === "weather") return renderWeather();
  if (tab === "server") return renderServer();
}

const USERS_PAGE_SIZE = 15;
let usersPage = 1;
let usersQuery = "";

function renderUsers() {
  const users = (cfg && cfg.users) ? cfg.users.slice() : [];

  const q = (usersQuery || "").trim().toLowerCase();
  const filtered = q ? users.filter(u => {
    const tgs = Array.isArray(u.talkgroups) ? u.talkgroups.join(",") : "";
    const perms = Array.isArray(u.permissions) ? u.permissions.join(",") : "";
    return (u.callsign || "").toLowerCase().includes(q) ||
           (u.role || "").toLowerCase().includes(q) ||
           tgs.toLowerCase().includes(q) ||
           perms.toLowerCase().includes(q);
  }) : users;

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / USERS_PAGE_SIZE));
  usersPage = Math.min(Math.max(1, usersPage), pages);

  const startIdx = (usersPage - 1) * USERS_PAGE_SIZE;
  const pageItems = filtered.slice(startIdx, startIdx + USERS_PAGE_SIZE);

  const rows = pageItems.map(u => {
    const tgs = Array.isArray(u.talkgroups) ? u.talkgroups.join(",") : "";
    const perms = Array.isArray(u.permissions) ? u.permissions.join(",") : "";
    return `<tr>
      <td>${esc(u.callsign)}</td>
      <td>${esc(u.role)}</td>
      <td>${esc(u.priority ?? "")}</td>
      <td>${u.banned ? "true" : "false"}</td>
      <td class="muted">${esc(tgs)}</td>
      <td class="muted">${esc(perms)}</td>
      <td class="action-row">
        <button class="btn btn-primary" data-act="edit-user" data-cs="${esc(u.callsign)}">Edit</button>
        <button class="btn btn-danger" data-act="del-user" data-cs="${esc(u.callsign)}">Delete</button>
      </td>
    </tr>`;
  }).join("");

  const cards = pageItems.map(u => {
    const tgs = Array.isArray(u.talkgroups) ? u.talkgroups.join(", ") : "";
    const perms = Array.isArray(u.permissions) ? u.permissions.join(", ") : "";
    return `
      <div class="mcard">
        <div class="mcard-head">
          <div>
            <div class="mcard-title">${esc(u.callsign)}</div>
            <div class="mcard-sub muted">${esc(u.role)} • priority ${esc(u.priority ?? 0)} • banned ${u.banned ? "true" : "false"}</div>
          </div>
          <div class="mcard-actions">
            <button class="btn btn-primary" data-act="edit-user" data-cs="${esc(u.callsign)}">Edit</button>
            <button class="btn btn-danger" data-act="del-user" data-cs="${esc(u.callsign)}">Del</button>
          </div>
        </div>
        <div class="mcard-body">
          <div class="mkv"><span class="muted">Talkgroups</span><div>${esc(tgs) || "<span class='muted'>(none)</span>"}</div></div>
          <div class="mkv"><span class="muted">Permissions</span><div>${esc(perms) || "<span class='muted'>(none)</span>"}</div></div>
        </div>
      </div>
    `;
  }).join("");

  const from = total === 0 ? 0 : (startIdx + 1);
  const to = Math.min(total, startIdx + USERS_PAGE_SIZE);

  tabContent.innerHTML = `
    <div class="section-header">
      <div class="section-actions">
        <button id="addUserBtn" class="btn btn-primary">Add user</button>
        <input id="usersSearch" class="search" placeholder="Search callsign / role / TG / permissions…" value="${esc(usersQuery)}" />
      </div>
    </div>

    <div class="desktop-only">
      <div class="table-scroll">
        <table class="table-mini">
          <thead>
            <tr>
              <th>Callsign</th><th>Role</th><th>Priority</th><th>Banned</th><th>Talkgroups</th><th>Permissions</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>${rows || `<tr><td colspan="7" class="muted">No users.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div class="mobile-only">
      <div class="mcard-list">${cards || `<div class="status-msg">No users.</div>`}</div>
    </div>

    <div class="pager">
      <div class="muted">Showing ${from}-${to} of ${total}</div>
      <div class="pager-buttons">
        <button class="btn" data-act="users-prev" ${usersPage <= 1 ? "disabled" : ""}>Prev</button>
        <span class="muted">Page ${usersPage} / ${pages}</span>
        <button class="btn" data-act="users-next" ${usersPage >= pages ? "disabled" : ""}>Next</button>
      </div>
    </div>
  `;

  const searchEl = tabContent.querySelector("#usersSearch");
  if (searchEl) {
    searchEl.addEventListener("input", debounce(() => {
      usersQuery = searchEl.value || "";
      usersPage = 1;
      renderUsers();
    }, 250));
  }

  const addBtn = tabContent.querySelector("#addUserBtn");
  if (addBtn) addBtn.addEventListener("click", () => openUserModal(null));

  tabContent.querySelectorAll("[data-act]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const act = btn.dataset.act;
      if (act === "users-prev") { usersPage = Math.max(1, usersPage - 1); return renderUsers(); }
      if (act === "users-next") { usersPage = usersPage + 1; return renderUsers(); }

      const cs = btn.dataset.cs;
      if (act === "edit-user") {
        const u = (cfg.users || []).find(x => x.callsign === cs);
        if (u) openUserModal(u);
        return;
      }
      if (act === "del-user") {
        if (!confirm(`Delete user ${cs}?`)) return;
        try {
          await api("/api/admin/users", { method: "POST", body: { op: "delete", callsign: cs } });
          setMsg(adminMsg, `Deleted ${cs}.`);
          await refreshAll();
          activeTab = "users";
          renderUsers();
        } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
      }
    });
  });
}

const TGS_PAGE_SIZE = 10;
let tgsPage = 1;
let tgsQuery = "";

function renderTalkgroups() {
  const tgs = (cfg && cfg.talkgroups) ? cfg.talkgroups.slice() : [];

  const q = (tgsQuery || "").trim().toLowerCase();
  const filtered = q ? tgs.filter(t => {
    return (t.name || "").toLowerCase().includes(q) ||
           (t.mode || "").toLowerCase().includes(q);
  }) : tgs;

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / TGS_PAGE_SIZE));
  tgsPage = Math.min(Math.max(1, tgsPage), pages);

  const startIdx = (tgsPage - 1) * TGS_PAGE_SIZE;
  const pageItems = filtered.slice(startIdx, startIdx + TGS_PAGE_SIZE);

  const rows = pageItems.map(t => `
    <tr>
      <td>${esc(t.name)}</td>
      <td>${esc(t.mode || "public")}</td>
      <td class="action-row">
        <button class="btn btn-primary" data-act="edit-tg" data-name="${esc(t.name)}">Edit</button>
        <button class="btn btn-danger" data-act="del-tg" data-name="${esc(t.name)}">Delete</button>
      </td>
    </tr>`).join("");

  const cards = pageItems.map(t => `
    <div class="mcard">
      <div class="mcard-head">
        <div>
          <div class="mcard-title">${esc(t.name)}</div>
          <div class="mcard-sub muted">mode: ${esc(t.mode || "public")}</div>
        </div>
        <div class="mcard-actions">
          <button class="btn btn-primary" data-act="edit-tg" data-name="${esc(t.name)}">Edit</button>
          <button class="btn btn-danger" data-act="del-tg" data-name="${esc(t.name)}">Del</button>
        </div>
      </div>
    </div>
  `).join("");

  const from = total === 0 ? 0 : (startIdx + 1);
  const to = Math.min(total, startIdx + TGS_PAGE_SIZE);

  tabContent.innerHTML = `
    <div class="section-header">
      <div class="section-actions">
        <button id="addTgBtn" class="btn btn-primary">Add talkgroup</button>
        <input id="tgsSearch" class="search" placeholder="Search talkgroups…" value="${esc(tgsQuery)}" />
      </div>
    </div>

    <div class="desktop-only">
      <div class="table-scroll">
        <table class="table-mini">
          <thead><tr><th>Name</th><th>Mode</th><th>Actions</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="3" class="muted">No talkgroups.</td></tr>`}</tbody>
        </table>
      </div>
    </div>

    <div class="mobile-only">
      <div class="mcard-list">${cards || `<div class="status-msg">No talkgroups.</div>`}</div>
    </div>

    <div class="pager">
      <div class="muted">Showing ${from}-${to} of ${total}</div>
      <div class="pager-buttons">
        <button class="btn" data-act="tgs-prev" ${tgsPage <= 1 ? "disabled" : ""}>Prev</button>
        <span class="muted">Page ${tgsPage} / ${pages}</span>
        <button class="btn" data-act="tgs-next" ${tgsPage >= pages ? "disabled" : ""}>Next</button>
      </div>
    </div>
  `;

  const searchEl = tabContent.querySelector("#tgsSearch");
  if (searchEl) {
    searchEl.addEventListener("input", debounce(() => {
      tgsQuery = searchEl.value || "";
      tgsPage = 1;
      renderTalkgroups();
    }, 250));
  }

  const addBtn = tabContent.querySelector("#addTgBtn");
  if (addBtn) addBtn.addEventListener("click", () => openTalkgroupModal(null));

  tabContent.querySelectorAll("[data-act]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const act = btn.dataset.act;
      if (act === "tgs-prev") { tgsPage = Math.max(1, tgsPage - 1); return renderTalkgroups(); }
      if (act === "tgs-next") { tgsPage = tgsPage + 1; return renderTalkgroups(); }

      const name = btn.dataset.name;
      if (act === "edit-tg") {
        const t = (cfg.talkgroups || []).find(x => x.name === name);
        if (t) openTalkgroupModal(t);
        return;
      }
      if (act === "del-tg") {
        if (!confirm(`Delete talkgroup ${name}?`)) return;
        try {
          await api("/api/admin/talkgroups", { method: "POST", body: { op: "delete", name } });
          setMsg(adminMsg, `Deleted ${name}.`);
          await refreshAll();
          activeTab = "talkgroups";
          renderTalkgroups();
        } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
      }
    });
  });
}

function renderBridges() {
  const bridges = cfg.bridges || {};
  const keys = Object.keys(bridges).sort();

  const rows = keys.map(tg => {
    const linkedArr = Array.isArray(bridges[tg]) ? bridges[tg] : [];
    const linked = linkedArr.join(",");
    return `
      <tr>
        <td>${esc(tg)}</td>
        <td class="muted">${esc(linked)}</td>
        <td class="action-row">
          <button class="btn btn-primary" data-act="edit-bridge" data-tg="${esc(tg)}">Edit</button>
          <button class="btn btn-danger" data-act="del-bridge" data-tg="${esc(tg)}">Delete</button>
        </td>
      </tr>`;
  }).join("");

  tabContent.innerHTML = `
    <div class="section-header">
      <div class="section-actions">
        <button id="addBridgeBtn" class="btn btn-primary">Add bridge</button>
      </div>
    </div>

    <div class="table-scroll">
      <table class="table-mini">
        <thead>
          <tr><th>Talkgroup</th><th>Linked</th><th>Actions</th></tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="3" class="muted">No bridges configured.</td></tr>`}</tbody>
      </table>
    </div>
  `;

  const addBtn = document.getElementById("addBridgeBtn");
  if (addBtn) addBtn.addEventListener("click", () => openBridgeModal(null));

  tabContent.querySelectorAll("[data-act]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const act = btn.dataset.act;
      const tg = btn.dataset.tg;

      if (act === "edit-bridge") {
        const linked = Array.isArray(bridges[tg]) ? bridges[tg] : [];
        return openBridgeModal({ talkgroup: tg, linked });
      }

      if (act === "del-bridge") {
        if (!confirm(`Delete bridge for talkgroup ${tg}?`)) return;
        try {
          await api("/api/admin/bridges", { method: "POST", body: { op: "delete", talkgroup: tg } });
          setMsg(adminMsg, `Deleted bridge for ${tg}.`);
          await refreshAll();
          activeTab = "bridges";
          renderBridges();
        } catch (e) {
          setMsg(adminMsg, "Error: " + e.message, false);
        }
      }
    });
  });
}

function renderPeers() {
  const peers = cfg.peers || [];
  const rows = peers.map(p => {
    const rules = Array.isArray(p.rules) ? p.rules.join(",") : "";
    return `
      <tr>
        <td>${esc(p.name)}</td>
        <td><input data-k="host" data-name="${esc(p.name)}" value="${esc(p.host)}" /></td>
        <td><input data-k="port" data-name="${esc(p.name)}" value="${esc(p.port)}" /></td>
        <td><input data-k="secret" data-name="${esc(p.name)}" value="${esc(p.secret || "")}" /></td>
        <td><input data-k="rules" data-name="${esc(p.name)}" value="${esc(rules)}" placeholder="local=remote:tx,..." /></td>
        <td class="action-row">
		  <button class="btn btn-primary" data-act="edit-peer" data-name="${esc(p.name)}">Edit</button>
          <button class="btn btn-danger" data-act="del-peer" data-name="${esc(p.name)}">Delete</button>
        </td>
      </tr>`;
  }).join("");

  tabContent.innerHTML = `
	<div class="section-header">
	  <div class="section-actions">
		<button id="addPeerBtn" class="btn btn-primary">Add peer</button>
	  </div>
	</div>

    <div class="table-scroll"><table class="table-mini">
      <thead><tr><th>Name</th><th>Host</th><th>Port</th><th>Secret</th><th>Rules</th><th>Actions</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="6" class="muted">No peers configured.</td></tr>`}</tbody>
    </table></div>
  `;

  const addBtn = document.getElementById("addPeerBtn");
  if (addBtn) addBtn.addEventListener("click", () => openPeerModal(null));

  tabContent.querySelectorAll("[data-act]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const name = btn.dataset.name;

	  if (btn.dataset.act === "edit-peer") {
		const p = (cfg.peers || []).find(x => x.name === name);
		if (p) openPeerModal(p);
	  }
      if (btn.dataset.act === "del-peer") {
        if (!confirm(`Delete peer ${name}?`)) return;
        try {
          await api("/api/admin/peers", { method: "POST", body: { op: "delete", name } });
          setMsg(adminMsg, `Deleted ${name}.`);
          await refreshAll();
        } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
        return;
      }
    });
  });

  document.getElementById("addPeerBtn").addEventListener("click", async () => {
    const name = document.getElementById("peerName").value.trim();
    const host = document.getElementById("peerHost").value.trim();
    const port = parseInt(document.getElementById("peerPort").value || "0", 10);
    const secret = document.getElementById("peerSecret").value;
    const rules = (document.getElementById("peerRules").value || "").split(",").map(x => x.trim()).filter(Boolean);
    if (!name || !host || !port) return setMsg(adminMsg, "Name, host, port are required.", false);
    try {
      await api("/api/admin/peers", { method: "POST", body: { op: "upsert", name, host, port, secret, rules } });
      setMsg(adminMsg, `Created ${name}.`);
      await refreshAll();
    } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
  });
}

function renderTime() {
  const t = cfg.time_announcement || {};
  const enabled = !!t.enabled;
  const folder = t.folder || "";
  const vol = typeof t.volume_factor === "number" ? t.volume_factor : 1.0;

  tabContent.innerHTML = `
    <div class="grid2">
      <div class="form-row"><label>Enabled</label>
        <select id="timeEnabled"><option value="false" ${enabled ? "" : "selected"}>false</option><option value="true" ${enabled ? "selected" : ""}>true</option></select>
      </div>
      <div class="form-row"><label>Folder</label><input id="timeFolder" value="${esc(folder)}" placeholder="wav/time" /></div>
      <div class="form-row"><label>Volume factor</label><input id="timeVol" value="${esc(vol)}" placeholder="1.0" /></div>
      <div class="form-row"><label></label><button class="btn btn-primary" id="timeSaveBtn">Save</button></div>
    </div>
  `;

  document.getElementById("timeSaveBtn").addEventListener("click", async () => {
    const enabled = document.getElementById("timeEnabled").value === "true";
    const folder = document.getElementById("timeFolder").value.trim();
    const vol = parseFloat(document.getElementById("timeVol").value || "1.0");
    const permil = Math.round((isFinite(vol) ? vol : 1.0) * 1000);
    try {
      await api("/api/admin/time_announcement", {
        method: "POST",
        body: { enabled, folder, volume_factor_permil: permil },
      });
      setMsg(adminMsg, "Saved time announcement.");
      await refreshAll();
    } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
  });
}

function renderWeather() {
  const w = cfg.weather || {};
  tabContent.innerHTML = `
    <div class="grid2">
      <div class="form-row"><label>Enabled</label>
        <select id="wEnabled"><option value="false" ${w.enabled ? "" : "selected"}>false</option><option value="true" ${w.enabled ? "selected" : ""}>true</option></select>
      </div>
      <div class="form-row"><label>Host IP</label><input id="wHost" value="${esc(w.weather_host_ip || "")}" /></div>
      <div class="form-row"><label>Talkgroup</label><input id="wTg" value="${esc(w.talkgroup || "")}" /></div>
      <div class="form-row"><label>Interval (sec)</label><input id="wInt" value="${esc(w.interval_sec ?? 1800)}" /></div>
      <div class="form-row"><label>API key</label><input id="wKey" value="${esc(w.api_key || "")}" /></div>
      <div class="form-row"><label>Lat</label><input id="wLat" value="${esc(w.lat || "")}" /></div>
      <div class="form-row"><label>Lon</label><input id="wLon" value="${esc(w.lon || "")}" /></div>
      <div class="form-row"><label>City key</label><input id="wCity" value="${esc(w.city_key || "")}" /></div>
      <div class="form-row"><label></label><button class="btn btn-primary" id="wSaveBtn">Save</button></div>
    </div>
  `;

  document.getElementById("wSaveBtn").addEventListener("click", async () => {
    const enabled = document.getElementById("wEnabled").value === "true";
    const weather_host_ip = document.getElementById("wHost").value.trim();
    const talkgroup = document.getElementById("wTg").value.trim();
    const interval_sec = parseInt(document.getElementById("wInt").value || "1800", 10);
    const api_key = document.getElementById("wKey").value;
    const lat = document.getElementById("wLat").value.trim();
    const lon = document.getElementById("wLon").value.trim();
    const city_key = document.getElementById("wCity").value.trim();
    try {
      await api("/api/admin/weather", { method: "POST", body: { enabled, weather_host_ip, talkgroup, interval_sec, api_key, lat, lon, city_key } });
      setMsg(adminMsg, "Saved weather.");
      await refreshAll();
    } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
  });
}

function renderServer() {
  tabContent.innerHTML = `
    <div class="grid2">
      <div class="form-row"><label>Server name</label><input id="sName" value="${esc(cfg.server_name || "")}" /></div>
      <div class="form-row"><label>Peer secret</label><input id="sPeerSecret" value="${esc(cfg.peer_secret || "")}" /></div>
      <div class="form-row"><label>Server port</label><input id="sPort" value="${esc(cfg.server_port)}" /></div>
      <div class="form-row"><label>Max talk ms</label><input id="sMax" value="${esc(cfg.max_talk_ms)}" /></div>
      <div class="form-row"><label>HTTP root</label><input id="sHttpRoot" value="${esc(cfg.http_root)}" /></div>
      <div class="form-row"><label>HTTP port</label><input id="sHttpPort" value="${esc(cfg.http_port)}" /></div>
      <div class="form-row"><label></label><button class="btn btn-primary" id="sSaveBtn">Save</button></div>
    </div>
  `;

  document.getElementById("sSaveBtn").addEventListener("click", async () => {
    const server_name = document.getElementById("sName").value.trim();
    const peer_secret = document.getElementById("sPeerSecret").value;
    const server_port = parseInt(document.getElementById("sPort").value || "0", 10);
    const max_talk_ms = parseInt(document.getElementById("sMax").value || "0", 10);
    const http_root = document.getElementById("sHttpRoot").value.trim();
    const http_port = parseInt(document.getElementById("sHttpPort").value || "0", 10);
    try {
      const r = await api("/api/admin/server", { method: "POST", body: { server_name, peer_secret, server_port, max_talk_ms, http_root, http_port } });
      setMsg(adminMsg, r.note || "Saved.");
      await refreshAll();
    } catch (e) { setMsg(adminMsg, "Error: " + e.message, false); }
  });
}

loginBtn.addEventListener("click", doLogin);
logoutBtn.addEventListener("click", doLogout);
refreshBtn.addEventListener("click", refreshAll);

pwEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") doLogin();
});

if (menuBtn) menuBtn.addEventListener("click", () => openDrawer());
if (drawerCloseBtn) drawerCloseBtn.addEventListener("click", () => closeDrawer());
if (drawerOverlay) drawerOverlay.addEventListener("click", () => closeDrawer());
if (drawer) {
  drawer.querySelectorAll("[data-tab]").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === tab);
      });
      activeTab = tab;
      closeDrawer();
      renderTab(activeTab);
    });
  });
}

if (modalCancelBtn) modalCancelBtn.addEventListener("click", () => closeModal());
if (modalCloseBtn) modalCloseBtn.addEventListener("click", () => closeModal());
if (modalSaveBtn) modalSaveBtn.addEventListener("click", () => saveModal());
if (modalOverlay) {
  modalOverlay.addEventListener("click", (e) => {
    if (e.target === modalOverlay) closeModal();
  });
}
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && modalOverlay && !modalOverlay.classList.contains("hidden")) closeModal();
});


tabsInit();

(async () => {
  if (!token) return showLogin();
  try {
    me = { callsign: "session", role: "?" };
    await refreshAll();
  } catch (_) {
    showLogin();
  }
})();
