"use strict";

// This application deliberately stores no credentials in browser storage.
const S = {
  token: "", config: null, configRevision: null, credentials: [], agents: [], jobs: [], job: null,
  route: "overview", jobId: null, connected: false, selected: new Set(),
  filters: { severity: "", model: "", text: "" }, reportSignature: "",
  pollTimer: null, polling: false, modalAction: null, modalOpener: null, preview: null, routeRevision: 0,
  importing: false, groupRelated: true, allowPartial: false, expandedFindings: new Set(),
};
const ACTIVE = new Set(["queued", "preparing", "running", "cancelling"]);
const TERMINAL = new Set(["completed", "failed", "timeout", "cancelled", "interrupted"]);
const STATUS = Object.assign(Object.create(null), { queued: "排队中", preparing: "准备代码", running: "运行中", cancelling: "正在停止", completed: "已完成", partial: "部分完成", failed: "失败", cancelled: "已取消", timeout: "已超时", interrupted: "已中断", ready: "已就绪", missing: "未检测到" });
const SEVERITY = Object.assign(Object.create(null), { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" });
const AGENT_NAMES = Object.assign(Object.create(null), { opencode: "OpenCode", codex: "Codex CLI", claude: "Claude Code", gemini: "Gemini CLI" });
const FORMATS = Object.assign(Object.create(null), { "openai-chat": "OpenAI Chat Completions", "openai-responses": "OpenAI Responses", anthropic: "Anthropic Messages", gemini: "Gemini Native" });
const AGENT_FORMATS = Object.assign(Object.create(null), { opencode: "openai-chat", codex: "openai-responses", claude: "anthropic", gemini: "gemini" });
const ICONS = {
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="m9 5 7 7-7 7"/>',
  back: '<path d="m14 6-6 6 6 6"/>',
  shield: '<path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  alert: '<path d="m12 3 10 17H2L12 3Z"/><path d="M12 9v5m0 3h.01"/>',
  edit: '<path d="m14 5 5 5M4 20l4-1L20 7a2 2 0 0 0-3-3L5 16l-1 4Z"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
  key: '<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 2-2m-5-1 2-2"/>',
  download: '<path d="M12 3v12m-4-4 4 4 4-4M4 15v5h16v-5"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 11-2l3 4M4 15l3 4a7 7 0 0 0 11-2"/>',
  github: '<circle cx="7" cy="5" r="2"/><circle cx="7" cy="19" r="2"/><circle cx="17" cy="6" r="2"/><path d="M7 7v10m10-9v2a5 5 0 0 1-5 5H7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
};
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clone = value => JSON.parse(JSON.stringify(value));
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.info}</svg>`;
const button = (label, action, kind = "", extra = "") => `<button class="button ${kind}" type="button" data-action="${action}" ${extra}>${label}</button>`;
const agentName = id => AGENT_NAMES[id] || id;
const status = value => `<span class="status-pill status-${Object.hasOwn(STATUS, value) ? value : "missing"}">${esc(STATUS[value] || value || "未知")}</span>`;
const severity = value => `<span class="tag severity-${Object.hasOwn(SEVERITY, value) ? value : "info"}">${esc(SEVERITY[value] || value)}</span>`;
const date = value => { const d = new Date(value); return value && !Number.isNaN(d.getTime()) ? d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "—"; };
const time = value => { const d = new Date(value); return value && !Number.isNaN(d.getTime()) ? d.toLocaleTimeString("zh-CN", { hour12: false }) : "—"; };
const duration = seconds => typeof seconds === "number" && Number.isFinite(seconds) ? `${seconds.toFixed(1)} 秒` : "—";
const jobName = target => String(target || "未命名任务").replace(/[/\\]+$/, "").split(/[/\\]/).pop().replace(/\.git$/, "") || target;
const isActive = job => job && ACTIVE.has(job.status);
const isImported = job => job?.origin === "imported" || job?.imported === true;
const MAX_IMPORT_BYTES = 32 * 1024 * 1024;
const MAX_PREVIEW_FINDINGS = 1000;
const EVENT_MESSAGES = Object.assign(Object.create(null), {
  "Review queued": "扫描任务已排队",
  "Preparing a filtered, stable code snapshot": "正在准备过滤后的代码快照",
  "Model reviews started": "模型审阅已启动",
  "Model queued": "等待空闲执行名额",
  "Model running": "正在分析代码",
  "Model completed": "审阅完成，结果已收集",
  "Model failed": "审阅失败，请查看实例错误",
  "Model timeout": "已达到单模型超时上限",
  "Model cancelled": "实例已取消",
  "Stopping model processes and cleaning their workspaces": "正在停止模型进程并清理工作目录",
  "Review cancelled; completed results were retained": "扫描已取消，已完成结果已保留",
  "Review finished": "扫描任务已结束",
  "The application stopped before this review finished": "服务停止时任务尚未完成",
});
const eventMessage = event => EVENT_MESSAGES[event.message] || event.message || STATUS[event.status] || event.status;
const credential = name => S.credentials.find(item => item.name === name);
const agent = id => S.agents.find(item => item.id === id);
const option = (value, label, selected = false) => `<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(label)}</option>`;
const heading = (title, subtitle, action = "", eyebrow = "SECURITY WORKSPACE") => `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1>${esc(title)}</h1><p class="page-subtitle">${esc(subtitle)}</p></div>${action}</div>`;
const empty = (title, description, action = "", compact = false) => `<div class="empty-state${compact ? " compact" : ""}"><div class="empty-icon">${icon("shield")}</div><h3>${esc(title)}</h3><p>${esc(description)}</p>${action}</div>`;

async function api(path, { method = "GET", body, raw = false } = {}) {
  const headers = { "X-Autoreviewer-Token": S.token };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let response;
  try { response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "same-origin" }); }
  catch { throw new Error("无法连接本地服务，请确认 autoreviewer ui 仍在运行。"); }
  if (!response.ok) {
    let message = `请求失败（HTTP ${response.status}）`;
    try { const data = await response.json(); if (typeof data.error === "string") message = data.error; } catch { /* Keep bounded, predictable error copy. */ }
    const error = new Error(message); error.status = response.status; throw error;
  }
  return raw ? response : response.status === 204 ? {} : response.json();
}
function notify(message, kind = "success") {
  const node = document.createElement("div"); node.className = `toast ${kind}`;
  const text = document.createElement("span"); text.textContent = message;
  const close = document.createElement("button"); close.type = "button"; close.textContent = "×"; close.setAttribute("aria-label", "关闭通知"); close.addEventListener("click", () => node.remove());
  node.append(text, close); $("#notifications").append(node);
  window.setTimeout(() => node.remove(), kind === "error" ? 12000 : 6000);
}
function setConnected(yes) {
  S.connected = yes; const node = $("#connection-state"); node.textContent = yes ? "服务已连接" : "连接中断"; node.classList.toggle("offline", !yes);
}
function modal(title, subtitle, body, action = null) {
  const el = $("#modal");
  if (!el.open) {
    const opener = document.activeElement?.closest("[data-action]");
    S.modalOpener = opener ? ["action", "id", "name"].filter(key => opener.dataset[key] !== undefined).map(key => `[data-${key}="${CSS.escape(opener.dataset[key])}"]`).join("") : null;
  }
  S.modalAction = action;
  $("#modal-content").innerHTML = `<div class="modal-header"><div><h2 id="modal-title">${esc(title)}</h2><p>${esc(subtitle)}</p></div><button type="button" class="icon-button" data-action="close-modal" aria-label="关闭">${icon("close")}</button></div><div class="modal-body"><div id="modal-error" hidden class="error-banner" role="alert"></div>${body}</div>`;
  if (!el.open) el.showModal();
  window.setTimeout(() => { const field = $("input:not([disabled]):not([type=checkbox]),textarea,select", el); if (field) field.focus(); }, 0);
}
function closeModal() { $("#modal").close(); $("#modal-content").replaceChildren(); S.modalAction = null; S.modalOpener = null; S.preview = null; }
async function finishConfigSave(form) {
  // A response must not replace a different form opened while it was pending.
  if (!form.isConnected) return;
  const inModal = !!form.closest("dialog");
  if (!inModal && $("#modal").open) return;
  const opener = S.modalOpener;
  if (inModal) closeModal();
  await route();
  ((opener && $(opener)) || $("#main-content")).focus({ preventScroll: true });
}
function modalError(message) { const node = $("#modal-error"); if (node) { node.hidden = false; node.textContent = message; } else notify(message, "error"); }
function modalActions(label = "保存配置", extra = "") { return `<div class="form-actions">${button("取消", "close-modal")}<button type="submit" class="button primary" ${extra}>${esc(label)}</button></div>`; }

function overviewStats() {
  const active = S.jobs.filter(isActive).length;
  const completed = S.jobs.filter(job => job.status === "completed" && !isImported(job)).length;
  const imported = S.jobs.filter(isImported).length;
  const findings = S.jobs.reduce((sum, job) => sum + (Number.isFinite(job.finding_count) ? job.finding_count : job.report?.findings?.length || 0), 0);
  return [
    ["任务与报告", S.jobs.length, `${completed} 个本机任务完成 · ${imported} 份导入报告`, "folder", ""],
    ["正在运行", active, "各模型独立工作目录", "activity", "teal"],
    ["待复核发现", findings, "跨任务累计报告记录", "shield", "amber"],
    ["已配置模型", S.config.models.length, `${Object.keys(S.config.providers).length} 个模型平台`, "layers", "blue"],
  ].map(([name, value, sub, ico, color]) => `<div class="stat-card"><div class="stat-top"><span>${name}</span><span class="stat-icon ${color}">${icon(ico)}</span></div><div class="stat-value">${value}</div><div class="stat-bottom">${esc(sub)}</div></div>`).join("");
}
function jobTable() {
  if (!S.jobs.length) return empty("开始第一次代码安全审阅", "配置模型与 CLI 后，选择代码目录或 GitHub 仓库。多个模型将并行分析，并将发现汇总到这里。", '<a href="#scan" class="button primary">' + icon("plus") + "新建扫描</a>");
  return `<div class="table-wrap"><table><thead><tr><th>审阅目标</th><th>状态</th><th>模型</th><th>发现</th><th>创建时间</th><th><span class="sr-only">操作</span></th></tr></thead><tbody>${S.jobs.map(job => `<tr><td><div class="task-cell"><span class="repo-icon">${icon("folder")}</span><div><a class="table-primary" href="#job/${encodeURIComponent(job.id)}" title="${esc(job.target)}">${esc(jobName(job.target))}</a><span class="table-secondary">${esc(job.target)}</span></div></div></td><td>${status(job.status)}${isImported(job) ? '<span class="tag imported-tag">已导入</span>' : ""}</td><td>${esc(job.model_count ?? job.runs?.length ?? "—")}</td><td>${esc(job.finding_count ?? job.report?.findings?.length ?? (isActive(job) ? "—" : 0))}</td><td class="no-wrap">${date(job.created_at || job.started_at)}</td><td><a class="table-link" href="#job/${encodeURIComponent(job.id)}">查看 →</a></td></tr>`).join("")}</tbody></table></div>`;
}
function renderOverview() {
  const available = S.agents.filter(item => item.available).length;
  const configured = S.credentials.filter(item => item.configured).length;
  $("#view").innerHTML = heading("安全审阅工作台", "让不同模型从各自的视角，审阅同一份代码。", '<div class="button-row">' + button(icon("download") + (S.importing ? "正在导入…" : "导入 JSON 报告"), "import-report", "", S.importing ? "disabled" : "") + '<a href="#scan" class="button primary">' + icon("plus") + "新建扫描</a></div>") + `<div id="overview-stats" class="stats-grid">${overviewStats()}</div><div class="section-grid"><section class="panel"><div class="panel-heading"><h2>任务与报告 <span id="job-count" class="count">${S.jobs.length}</span></h2><small>最新任务优先</small></div><div id="jobs-table">${jobTable()}</div></section><aside class="stack"><section class="panel"><div class="panel-heading"><h2>开始使用</h2><span class="tag">3 STEPS</span></div><div class="quick-steps"><div class="quick-step"><span class="step-number ${available ? "done" : ""}">01</span><div><h3>连接本地 Code Agent</h3><p>已检测到 ${available} 个可用 CLI。</p><a href="#agents">管理 CLI →</a></div></div><div class="quick-step"><span class="step-number ${configured ? "done" : ""}">02</span><div><h3>配置模型与密钥</h3><p>使用已有的平台账户，组合不同模型。</p><a href="#models">配置模型 →</a></div></div><div class="quick-step"><span class="step-number ${S.jobs.length ? "done" : ""}">03</span><div><h3>启动并行审阅</h3><p>选择目标仓库，在独立代码副本中分析。</p><a href="#scan">创建任务 →</a></div></div></div></section><div class="info-note">${icon("info")}<h3>每一条发现，都有来源</h3><p>保留模型、文件位置与代码证据。多模型一致是复核线索，确认问题后再提交 GitHub Issue。</p></div></aside></div>`;
}
function updateOverview() {
  if ($("#overview-stats")) $("#overview-stats").innerHTML = overviewStats();
  if ($("#jobs-table")) $("#jobs-table").innerHTML = jobTable();
  if ($("#job-count")) $("#job-count").textContent = S.jobs.length;
}
function scanAvailability(active) {
  return active ? `<div class="info-note warning mb"><h3>已有扫描正在运行</h3><p>当前服务同时执行一个扫描任务，任务内可并行运行多个模型。<a href="#job/${encodeURIComponent(active.id)}">查看当前任务 →</a></p></div>` : "";
}
function updateScanAvailability() {
  const form = $("#scan-form");
  if (!form) return;
  const active = S.jobs.find(isActive);
  $("#scan-availability").innerHTML = scanAvailability(active);
  $('button[type="submit"]', form).disabled = !!active || form.dataset.busy === "true";
}
function renderScan() {
  const active = S.jobs.find(isActive);
  $("#view").innerHTML = heading("新建代码扫描", "选择审阅目标与模型，一次启动多个独立分析实例。", "", "NEW SECURITY REVIEW") + `<div class="section-grid"><form id="scan-form" class="panel"><div class="panel-heading"><h2>审阅目标</h2><span class="tag">01</span></div><div class="panel-body"><div id="scan-availability">${scanAvailability(active)}</div><div class="radio-group"><label class="radio-card"><input type="radio" name="target_type" value="local" checked>本地代码目录</label><label class="radio-card"><input type="radio" name="target_type" value="github">GitHub 仓库</label></div><div class="form-grid"><div class="field full"><label for="scan-target" id="target-label">代码目录 <span class="required">*</span></label><input id="scan-target" name="target" required autocomplete="off" placeholder="/path/to/your/project"><span class="field-help" id="target-help">填写运行 autoreviewer 服务的机器上的目录路径。</span></div><div class="field full" id="ref-field" hidden><label for="scan-ref">分支或标签 <span class="optional">可选</span></label><input id="scan-ref" name="ref" disabled placeholder="默认分支" autocomplete="off"></div></div><div class="form-divider"></div><div class="field-row"><h2 class="section-title">选择审阅模型 <span class="count">${S.config.models.length}</span></h2><a href="#models" class="button text small">管理模型 →</a></div><p class="field-help">每个模型启动一个 CLI 实例，使用独立的代码副本和配置。</p><div class="model-options">${S.config.models.map(model => `<label class="model-option"><input type="checkbox" name="models" value="${esc(model.id)}" checked><span><strong>${esc(model.id)}</strong><small>${esc(model.model)} · ${esc(agentName(model.agent))}</small></span>${status(agent(model.agent)?.available ? "ready" : "missing")}</label>`).join("")}</div><div class="form-divider"></div><h2 class="section-title">运行设置</h2><div class="form-grid"><div class="field"><label for="scan-concurrency">最大并发数</label><input id="scan-concurrency" name="concurrency" type="number" min="1" max="32" required value="${S.config.scan.concurrency}"><span class="field-help">超过并发上限的模型会等待空闲名额。</span></div><div class="field"><label for="scan-timeout">单模型超时（秒）</label><input id="scan-timeout" name="timeout_seconds" type="number" min="1" max="86400" required value="${S.config.scan.timeout_seconds}"><span class="field-help">超时终止该实例，保留其他模型的结果。</span></div></div><div class="form-actions"><a href="#overview" class="button">返回概览</a><button type="submit" class="button primary"${active ? " disabled" : ""}>${icon("shield")}启动安全审阅</button></div></div></form><aside class="stack"><div class="info-note"><h3>扫描如何进行</h3><p>1. 创建经过过滤的代码快照<br>2. 为每个模型准备独立工作目录<br>3. 并行启动已安装的 CLI<br>4. 校验发现并生成汇总报告</p></div><div class="info-note"><h3>开始前确认</h3><p>所选 CLI 已安装，模型 API Key 已配置。代码会发送至所选模型平台，请选择你有权分析的仓库。</p></div><div class="info-note"><h3>保留真实执行状态</h3><p>失败、超时与完成分别显示。未收集到结果的实例不会被计为“未发现问题”。</p></div></aside></div>`;
}
function providerCard(id, item) {
  const key = credential(item.api_key_env);
  return `<div class="provider-card"><div class="provider-heading"><div class="provider-name"><span class="provider-avatar">${esc(id.slice(0, 1).toUpperCase())}</span><h3>${esc(id)}</h3></div><div class="button-row">${button(icon("edit"), "edit-provider", "small", `data-id="${esc(id)}" aria-label="编辑平台 ${esc(id)}"`)}<button type="button" class="icon-button danger" data-action="delete-provider" data-id="${esc(id)}" aria-label="删除平台 ${esc(id)}">${icon("trash")}</button></div></div><p class="provider-url mono">${esc(item.base_url)}</p><span class="tag">${esc(FORMATS[item.api_format] || item.api_format)}</span><div class="provider-footer"><span class="key-state ${key?.configured ? "ready" : ""}">${key?.configured ? "●" : "○"} ${!item.api_key_env ? "无需 API Key" : key?.configured ? key.source === "session" ? "密钥已配置 · 当前会话" : "密钥已配置 · 环境变量" : "尚未配置密钥"}</span>${item.api_key_env ? button(icon("key") + "设置密钥", "credential", "text small", `data-name="${esc(item.api_key_env)}"`) : ""}</div></div>`;
}
function renderModels() {
  $("#view").innerHTML = heading("模型与平台", "按平台管理连接信息，为每个审阅模型选择合适的 CLI。", '<div class="button-row">' + button(icon("download") + "导出配置", "export-config") + button(icon("plus") + "添加模型", "add-model") + "</div>") + `<section class="panel"><div class="panel-heading"><h2>模型平台 <span class="count">${Object.keys(S.config.providers).length}</span></h2>${button(icon("plus") + "添加平台", "add-provider", "small")}</div><div class="provider-grid">${Object.entries(S.config.providers).map(([id, item]) => providerCard(id, item)).join("")}</div></section><section class="panel"><div class="panel-heading"><h2>审阅模型 <span class="count">${S.config.models.length}</span></h2><small>相同平台可配置多个模型</small></div><div class="table-wrap"><table><thead><tr><th>名称 / 模型 ID</th><th>平台</th><th>Code Agent</th><th>兼容性</th><th>操作</th></tr></thead><tbody>${S.config.models.map(model => { const compatible = !AGENT_FORMATS[model.agent] || AGENT_FORMATS[model.agent] === S.config.providers[model.provider]?.api_format; return `<tr><td><strong class="table-primary">${esc(model.id)}</strong><span class="table-secondary mono" title="${esc(model.model)}">${esc(model.model)}</span></td><td>${esc(model.provider)}</td><td>${esc(agentName(model.agent))}</td><td>${compatible ? '<span class="tag">协议匹配</span>' : '<span class="tag severity-medium">协议不匹配</span>'}</td><td><div class="button-row"><button class="icon-button" type="button" data-action="edit-model" data-id="${esc(model.id)}" aria-label="编辑模型 ${esc(model.id)}">${icon("edit")}</button><button class="icon-button danger" type="button" data-action="delete-model" data-id="${esc(model.id)}" aria-label="删除模型 ${esc(model.id)}">${icon("trash")}</button></div></td></tr>`; }).join("")}</tbody></table></div></section><div class="info-note mt"><h3>密钥只用于当前服务会话</h3><p>网页输入的密钥仅保存在服务内存中，重启服务后需重新输入，也可在启动前设置对应环境变量。配置文件只保存环境变量名称。协议匹配与本地 CLI 可用不代表模型接口已通过实际调用验证。</p></div>`;
}
function renderAgents() {
  $("#view").innerHTML = heading("CLI 管理", "连接机器上已安装的 Code Agent，选择各自支持的模型接口。", button(icon("plus") + "添加自定义 CLI", "add-agent")) + `<div class="agent-grid">${Object.entries(S.config.agents || {}).map(([id, item]) => `<section class="panel agent-card"><div class="agent-head"><span class="agent-avatar">${icon("terminal")}</span><div><h3>${esc(agentName(id))}</h3><p>${esc(AGENT_FORMATS[id] ? FORMATS[AGENT_FORMATS[id]] : "自定义命令适配器")}</p></div>${status(agent(id)?.available ? "ready" : "missing")}</div><p class="field-help">${AGENT_FORMATS[id] ? "通过本地可执行文件启动，每个模型使用独立配置。" : "使用参数模板接收模型与目标目录，输出符合约定的 JSON。"}</p><div class="command-box mono">${esc(JSON.stringify(item.command || [id]))}</div><div class="agent-footer"><span>仅检测命令路径，不调用模型</span>${button(icon("edit") + "配置命令", "edit-agent", "small", `data-id="${esc(id)}"`)}</div></section>`).join("")}</div><div class="info-note mt"><h3>在终端安装，在这里连接</h3><p>请先按各 CLI 的官方说明完成安装；若程序不在 PATH 中，可配置可执行文件的绝对路径。此处不会自动安装依赖。目录与配置隔离用于减少相互影响，目前没有容器级文件访问隔离。</p></div>`;
}
function renderGitHub() {
  const github = S.config.github || {};
  const key = credential(github.token_env || "GITHUB_TOKEN");
  $("#view").innerHTML = heading("GitHub 集成", "设置目标仓库，在结果审阅后预览并提交选中的发现。", "", "REPOSITORY INTEGRATION") + `<div class="section-grid"><form id="github-form" class="panel"><div class="panel-heading"><h2>仓库配置</h2>${github.repository ? status("ready") : '<span class="tag">尚未配置</span>'}</div><div class="panel-body"><div class="form-grid"><div class="field full"><label for="github-repository">仓库名称</label><input name="repository" id="github-repository" value="${esc(github.repository)}" placeholder="owner/repository" autocomplete="off" required><span class="field-help">用于私有仓库访问和提交 Issue，请填写组织或用户名 / 仓库名。</span></div><div class="field full"><label for="github-token-env">Token 环境变量名</label><input id="github-token-env" name="token_env" value="${esc(github.token_env || "GITHUB_TOKEN")}" placeholder="GITHUB_TOKEN" required pattern="[A-Za-z_][A-Za-z0-9_]*" autocomplete="off"></div><div class="field full"><label for="github-labels">Issue 标签 <span class="optional">可选</span></label><input id="github-labels" name="labels" value="${esc((github.labels || []).join(", "))}" placeholder="security, autoreviewer" autocomplete="off"><span class="field-help">使用英文逗号分隔，标签需已存在于仓库中。</span></div></div><div class="form-divider"></div><h3 class="section-title">访问凭据</h3><p class="field-help">${key?.configured ? `已从${key.source === "session" ? "当前服务会话" : "环境变量"}读取 Token。` : "尚未配置 Token，可先保存仓库配置，再设置凭据。"}</p>${github.repository ? button(icon("key") + "设置 GitHub Token", "credential", "mt", `data-name="${esc(github.token_env || "GITHUB_TOKEN")}"`) : ""}<div class="form-actions">${github.repository ? button("移除集成", "delete-github", "danger") : ""}<button type="submit" class="button primary">保存仓库配置</button></div></div></form><aside class="stack"><div class="info-note"><h3>权限按需要授予</h3><p>访问私有代码需要 Contents 读取权限；创建 Issue 需要 Issues 写入权限。仅为目标仓库授予实际需要的权限。</p></div><div class="info-note"><h3>先复核，再发布</h3><p>扫描不会自动创建 Issue。在任务结果中选择发现，预览标题和正文，确认仓库后点击发布。部分完成的扫描需要单独选择允许发布。</p></div></aside></div>`;
}
function renderJobShell(job) {
  S.reportSignature = "";
  $("#view").innerHTML = `<a href="#overview" class="back-link">${icon("back")}返回任务概览</a><div id="job-heading"></div><div id="job-error"></div><section class="panel mb"><div class="panel-heading"><h2>模型执行情况</h2><div id="job-summary"></div></div><div class="panel-body"><div id="job-progress"></div><div id="job-runs" class="run-grid"></div></div></section><section class="panel mb"><div class="panel-heading"><h2>运行动态</h2><small>状态事件 · 不展示模型内部推理</small></div><div id="job-events" class="events" aria-live="polite"></div></section><section class="panel" id="findings-panel"><div class="panel-heading"><h2>审阅发现 <span class="count" id="findings-count">0</span></h2><div id="report-downloads" class="button-row"></div></div><div id="findings-controls"></div><div id="findings-list"></div></section>`;
  updateJob(job, true);
}
function auditGuidance(run) {
  const guidance = run.audit_guidance;
  const source = "https://github.com/cloudflare/security-audit-skill";
  if (!guidance || guidance.id !== "cloudflare-security-audit" || guidance.source !== source || guidance.mode !== "guidance-readonly" || typeof guidance.commit !== "string" || guidance.commit.length !== 40 || !/^[0-9a-f]{40}$/i.test(guidance.commit)) return "";
  const url = `${source}/commit/${guidance.commit}`;
  return `<p class="run-model audit-guidance">审计指导：<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Cloudflare Security Audit · 只读指导 · ${esc(guidance.commit.slice(0, 12))}</a></p>`;
}
function updateJob(job, force = false) {
  if (!job || !$("#job-heading")) return;
  const runs = job.runs || job.report?.runs || [];
  const count = runs.filter(run => TERMINAL.has(run.status)).length;
  const finished = !isActive(job);
  const imported = isImported(job);
  const anotherActive = S.jobs.some(item => item.id !== job.id && isActive(item));
  const retryDisabled = anotherActive ? 'disabled title="请等待当前扫描结束"' : "";
  const unsuccessful = runs.some(run => ["failed", "timeout", "cancelled", "interrupted"].includes(run.status));
  const actions = isActive(job)
    ? button(icon("stop") + (job.status === "cancelling" ? "正在停止…" : "取消扫描"), "cancel-job", "danger", job.status === "cancelling" ? "disabled" : "")
    : (imported ? "" : (unsuccessful ? button(icon("refresh") + "重试失败模型", "retry-failed", "primary", retryDisabled) : "") + button("重新扫描", "retry-all", "", retryDisabled)) + '<a href="#scan" class="button">' + icon("plus") + "新建扫描</a>";
  const lineage = job.parent_job_id ? `<p class="lineage">本任务${job.retry_mode === "failed" ? "重试了未完成的模型" : "重新扫描了全部原模型"}，<a href="#job/${encodeURIComponent(job.parent_job_id)}">查看原任务 →</a></p>` : "";
  const provenance = imported ? `<div class="info-note imported-notice"><h3>已导入的报告</h3><p>来源文件：<span class="mono">${esc(job.source_name || "JSON 报告")}</span>。这是外部报告记录，导入过程没有运行 CLI 或验证其中的发现。</p></div>` : "";
  $("#job-heading").innerHTML = `<div class="page-heading"><div><p class="eyebrow">SECURITY REVIEW</p><h1>${esc(jobName(job.target))}</h1><p class="task-target mono">${esc(job.target)}</p><div class="task-header-meta">${status(job.status)}${imported ? '<span class="tag imported-tag">已导入</span>' : ""}<span>${esc(job.id)}</span><span>${imported ? "导入于" : "创建于"} ${date(job.created_at || job.started_at)}</span>${job.ref ? `<span>分支 ${esc(job.ref)}</span>` : ""}</div>${lineage}</div><div class="button-row">${actions}</div></div>${provenance}`;
  $("#job-error").innerHTML = [job.error, job.persistence_error].filter(Boolean).map(message => `<div class="error-banner">${esc(message)}</div>`).join("");
  $("#job-summary").innerHTML = `<small>${count} / ${runs.length} 个模型已结束</small>`;
  $("#job-progress").innerHTML = `<div class="progress-track"><progress value="${count}" max="${Math.max(runs.length, 1)}" aria-label="已结束模型数量"></progress></div><div class="progress-label"><span>${imported ? "执行状态来自导入报告" : finished ? "本次执行已结束" : job.status === "cancelling" ? "正在终止实例并保存已完成结果" : "各实例独立执行，完成结果陆续显示"}</span><span>${runs.filter(run => run.status === "completed").length} 个成功</span></div>`;
  $("#job-runs").innerHTML = runs.length ? runs.map(run => `<article class="run-card"><div class="run-head"><strong>${esc(run.model)}</strong>${status(run.status)}</div><p class="run-model mono">${esc(run.model_name || run.model)}</p>${auditGuidance(run)}${run.error ? `<p class="run-error">${esc(run.error)}</p>` : ""}<div class="run-footer"><span>${esc(agentName(run.agent || ""))} · ${esc(run.provider || "")}</span><span>${run.status === "completed" ? `${run.findings?.length ?? run.finding_count ?? 0} 条发现 · ` : ""}${duration(run.duration_seconds)}</span></div></article>`).join("") : '<p class="field-help">正在准备所选模型…</p>';
  const events = job.events || [];
  const eventsNode = $("#job-events");
  const nearBottom = eventsNode.scrollHeight - eventsNode.scrollTop - eventsNode.clientHeight < 30;
  eventsNode.innerHTML = events.length ? events.slice(-80).map(event => `<div class="event"><time>${time(event.at)}</time><p>${event.model ? `<strong>${esc(event.model)}</strong>` : ""}${esc(eventMessage(event))}</p></div>`).join("") : '<p class="field-help">没有可用的任务状态记录。</p>';
  if (nearBottom) eventsNode.scrollTop = eventsNode.scrollHeight;
  const signature = JSON.stringify([job.status, job.report?.status, job.report?.findings || null, job.finding_groups || []]);
  if (force || signature !== S.reportSignature) {
    S.reportSignature = signature;
    const findings = job.report?.findings || [];
    const existing = new Set(findings.map(item => item.fingerprint));
    S.selected = new Set([...S.selected].filter(item => existing.has(item)));
    const focused = document.activeElement;
    const focusId = focused?.id;
    const caret = focusId === "finding-text" ? [focused.selectionStart, focused.selectionEnd] : null;
    $("#findings-count").textContent = findings.length;
    $("#report-downloads").innerHTML = job.report ? button(icon("download") + "JSON", "download-json", "small") + button(icon("download") + "Markdown", "download-markdown", "small") : "";
    const checkpoint = isActive(job) && job.report ? '<div class="checkpoint-notice" role="status"><strong>阶段结果，扫描仍在进行</strong><span>下方保留已完成模型的发现；其余实例结束后继续汇总。下载的是当前阶段报告，发布 Issue 需等待任务结束。</span></div>' : "";
    const publishDisabled = isActive(job) ? 'disabled title="扫描结束后可预览并发布"' : S.config.github ? "" : 'disabled title="请先配置 GitHub 集成"';
    const filters = findings.length ? `<div class="filters"><label class="sr-only" for="finding-text">按标题或文件筛选</label><input id="finding-text" class="filter-input" placeholder="搜索标题、文件或 CWE…" value="${esc(S.filters.text)}"><label class="sr-only" for="finding-severity">严重程度</label><select id="finding-severity" class="filter-select">${option("", "全部严重程度", !S.filters.severity)}${Object.entries(SEVERITY).map(([id, name]) => option(id, name, id === S.filters.severity)).join("")}</select><label class="sr-only" for="finding-model">来源模型</label><select id="finding-model" class="filter-select">${option("", "全部模型", !S.filters.model)}${[...new Set(findings.flatMap(item => item.models || []))].map(id => option(id, id, id === S.filters.model)).join("")}</select></div><div class="grouping-toolbar"><label class="inline-label"><input type="checkbox" id="group-related" ${S.groupRelated ? "checked" : ""}>按相同位置和 CWE 查看候选组</label><span>保留每条原始发现，不自动合并或确认漏洞。</span></div><div class="findings-toolbar"><label class="inline-label"><input type="checkbox" id="select-visible">选择当前结果 <span id="selected-count" class="muted"></span></label><div class="button-row">${job.report.status === "partial" && !isActive(job) ? `<label class="inline-label"><input type="checkbox" id="allow-partial" ${S.allowPartial ? "checked" : ""}>允许部分结果</label>` : ""}${button(icon("github") + "预览 GitHub Issue", "preview-issues", "small", publishDisabled)}</div></div><p id="selection-limit" class="field-help" role="status" hidden></p>` : "";
    $("#findings-controls").innerHTML = checkpoint + filters;
    renderFindings();
    if (["finding-text", "finding-severity", "finding-model", "group-related", "allow-partial"].includes(focusId)) {
      const replacement = document.getElementById(focusId);
      if (replacement) { replacement.focus({ preventScroll: true }); if (caret) replacement.setSelectionRange(...caret); }
    }
  }
}
function visibleFindings() {
  return (S.job?.report?.findings || []).filter(item => (!S.filters.severity || item.severity === S.filters.severity) && (!S.filters.model || (item.models || []).includes(S.filters.model)) && (!S.filters.text || `${item.title} ${item.file} ${item.cwe || ""}`.toLowerCase().includes(S.filters.text.toLowerCase())));
}
function findingObservations(item) {
  const observations = item.observations?.length ? item.observations : [item];
  const visible = S.filters.model ? observations.filter(observation => (observation.models || []).includes(S.filters.model)) : observations;
  const note = observations.length > 1 ? '<p class="field-help">汇总严重程度采用所有模型报告的最高值。以下保留各模型的证据、置信度与建议；模型一致不代表漏洞已确认。</p>' : "";
  return note + visible.map(observation => `<section class="model-observation" data-observation-models="${esc((observation.models || []).join(","))}"><div class="badge-row"><strong>来源模型：${esc((observation.models || []).join("、"))}</strong>${severity(observation.severity)}<span class="tag">模型置信度：${esc({ high: "高", medium: "中", low: "低" }[observation.confidence] || observation.confidence)}</span></div><div><h4>问题描述</h4><p>${esc(observation.description)}</p></div><div><h4>代码证据</h4><div class="evidence"><pre>${esc(observation.evidence)}</pre></div></div><div><h4>模型建议 · 需要复核</h4><p>${esc(observation.recommendation)}</p></div></section>`).join("");
}
function findingCard(item) {
  return `<article class="finding" data-finding-id="${esc(item.fingerprint)}"><div class="finding-header"><input type="checkbox" data-fingerprint="${esc(item.fingerprint)}" ${S.selected.has(item.fingerprint) ? "checked" : ""} aria-label="选择发现 ${esc(item.title)}"><div class="finding-main"><div class="finding-title">${severity(item.severity)}<h3>${esc(item.title)}</h3><span class="tag">待人工复核</span></div><div class="finding-meta"><span class="mono">${esc(item.file)}:${esc(item.line)}</span><span>${esc(item.cwe || "CWE 未指定")}</span><span>来源：${esc((item.models || []).join("、"))}</span></div><details class="finding-details" ${S.expandedFindings.has(item.fingerprint) ? "open" : ""}><summary>查看证据与修复建议</summary><div class="finding-content">${findingObservations(item)}<p class="field-help">发现标识：<span class="mono">${esc(item.fingerprint)}</span></p></div></details></div></div></article>`;
}
function groupedFindings(findings) {
  const groups = Array.isArray(S.job?.finding_groups) ? S.job.finding_groups : [];
  const byFingerprint = new Map();
  for (const group of groups) {
    if (group.record_count > 1 && Array.isArray(group.fingerprints)) {
      for (const fingerprint of group.fingerprints) byFingerprint.set(fingerprint, group);
    }
  }
  const rendered = new Set();
  return findings.map(item => {
    const group = byFingerprint.get(item.fingerprint);
    if (!group) return findingCard(item);
    if (rendered.has(group.id)) return "";
    rendered.add(group.id);
    const members = findings.filter(candidate => group.fingerprints.includes(candidate.fingerprint));
    return `<section class="finding-group" data-group-id="${esc(group.id)}"><div class="finding-group-heading"><div><span class="tag">同位置候选组</span><strong class="mono">${esc(group.file)}:${esc(group.line)}</strong><span>${esc(group.cwe)}</span></div><span>当前 ${members.length} 条 / 组内 ${esc(group.record_count)} 条记录</span></div><p class="finding-group-note">${esc((group.models || []).join("、"))} 报告了同位置、同 CWE 的候选问题，是否属于同一漏洞仍需复核。</p>${members.map(findingCard).join("")}</section>`;
  }).join("");
}
function renderFindings() {
  const node = $("#findings-list"); if (!node) return;
  for (const details of $$(".finding-details", node)) {
    const fingerprint = details.closest("[data-finding-id]")?.dataset.findingId;
    if (fingerprint) { if (details.open) S.expandedFindings.add(fingerprint); else S.expandedFindings.delete(fingerprint); }
  }
  if (!S.job?.report) { node.innerHTML = empty(isActive(S.job) ? "等待第一个模型完成审阅" : "此任务没有生成审阅报告", isActive(S.job) ? "完成模型的发现会陆续显示，并保存为阶段报告。" : "请检查运行状态与错误信息。失败或中断不代表代码没有问题。", "", true); return; }
  if (!S.job.report.findings?.length) { node.innerHTML = empty(isActive(S.job) ? "当前阶段尚未收集到发现" : "未收集到有效发现", isActive(S.job) ? "其他实例仍在运行，请结合上方模型状态判断完成情况。" : S.job.report.status === "completed" ? "本次完成的模型没有报告问题，这不代表代码已被证明安全。" : "任务未全部完成，请结合失败或取消的模型状态判断审阅覆盖范围。", "", true); return; }
  const findings = visibleFindings();
  node.innerHTML = findings.length ? (S.groupRelated ? groupedFindings(findings) : findings.map(findingCard).join("")) + '<p class="report-note">发现数量为报告中的原始记录数。候选分组只关联相同文件、行号和 CWE 的记录，不代表漏洞已确认或语义去重。</p>' : empty("没有匹配的发现", "调整严重程度、模型或关键词筛选。", "", true);
  updateSelection();
}
function updateSelection() {
  if ($("#selected-count")) $("#selected-count").textContent = `已选 ${S.selected.size} 条`;
  const visible = visibleFindings(); const box = $("#select-visible");
  if (box) { const selectedCount = visible.filter(item => S.selected.has(item.fingerprint)).length; box.checked = !!visible.length && selectedCount === visible.length; box.indeterminate = selectedCount > 0 && selectedCount < visible.length; }
  const limit = $("#selection-limit");
  const tooMany = S.selected.size > MAX_PREVIEW_FINDINGS;
  if (limit) { limit.hidden = !tooMany; limit.textContent = tooMany ? `每次最多预览 ${MAX_PREVIEW_FINDINGS} 条发现，当前已选 ${S.selected.size} 条。请取消部分选择后再预览。` : ""; }
  const preview = $('[data-action="preview-issues"]');
  if (preview) preview.disabled = tooMany || isActive(S.job) || !S.config.github;
}

function providerDialog(id = null) {
  const item = id ? S.config.providers[id] : { base_url: "", api_key_env: "", api_format: "openai-chat" };
  modal(id ? "编辑模型平台" : "添加模型平台", "设置平台的 API 地址与协议，密钥在保存后单独配置。", `<form id="provider-form"><div class="form-grid"><div class="field full"><label for="provider-id">平台标识</label><input name="id" id="provider-id" value="${esc(id)}" required pattern="[A-Za-z0-9](?:[A-Za-z0-9_.]|-){0,79}" placeholder="例如 nvidia" ${id ? "readonly" : ""}></div><div class="field full"><label for="provider-url">Base URL</label><input name="base_url" id="provider-url" type="url" value="${esc(item.base_url)}" required placeholder="https://integrate.api.nvidia.com/v1"><span class="field-help">远程地址需要 HTTPS，本地服务可使用 HTTP 回环地址。</span></div><div class="field full"><label for="provider-format">API 协议</label><select name="api_format" id="provider-format">${Object.entries(FORMATS).map(([value, label]) => option(value, label, value === item.api_format)).join("")}</select></div><div class="field full"><label for="provider-key-env">API Key 环境变量名 <span class="optional">可选</span></label><input name="api_key_env" id="provider-key-env" value="${esc(item.api_key_env)}" placeholder="NVIDIA_API_KEY" pattern="[A-Za-z_][A-Za-z0-9_]*" autocomplete="off"><span class="field-help">填写变量名而非密钥。无需鉴权的本地接口可留空。</span></div></div>${modalActions()}</form>`, id);
}
function modelDialog(id = null) {
  const item = id ? S.config.models.find(model => model.id === id) : { provider: Object.keys(S.config.providers)[0], model: "", agent: "opencode" };
  modal(id ? "编辑审阅模型" : "添加审阅模型", "每一项配置对应一个独立的 CLI 审阅实例。", `<form id="model-form"><div class="form-grid"><div class="field full"><label for="model-id">实例名称</label><input name="id" id="model-id" value="${esc(id)}" required pattern="[A-Za-z0-9](?:[A-Za-z0-9_.]|-){0,79}" placeholder="例如 reviewer-nemotron"></div><div class="field full"><label for="model-name">平台模型 ID</label><input name="model" id="model-name" value="${esc(item.model)}" required placeholder="平台提供的完整模型标识" autocomplete="off"></div><div class="field"><label for="model-provider">模型平台</label><select name="provider" id="model-provider">${Object.keys(S.config.providers).map(value => option(value, value, value === item.provider)).join("")}</select></div><div class="field"><label for="model-agent">Code Agent</label><select name="agent" id="model-agent">${Object.keys(S.config.agents || {}).map(value => option(value, agentName(value), value === item.agent)).join("")}</select></div></div><p class="field-help mt" id="model-compatibility"></p>${modalActions()}</form>`, id);
  showCompatibility();
}
function showCompatibility() {
  const field = $("#model-compatibility"); if (!field) return;
  const id = $("#model-agent").value; const provider = S.config.providers[$("#model-provider").value]; const required = AGENT_FORMATS[id];
  field.textContent = required ? provider?.api_format === required ? `${agentName(id)} 使用 ${FORMATS[required]}，所选平台协议匹配。` : `${agentName(id)} 需要 ${FORMATS[required]}，请调整平台或 CLI。` : "自定义适配器需要按其输出约定配置命令与参数。";
}
function credentialDialog(name) {
  const info = credential(name);
  modal("设置访问凭据", "输入值仅保存在当前服务进程内存中，不写入配置文件。", `<form id="credential-form"><div class="field"><label for="credential-value">${esc(name)}</label><input id="credential-value" name="value" type="password" autocomplete="new-password" spellcheck="false" placeholder="粘贴 API Key 或 Token" required><span class="field-help">${info?.configured ? "已有可用凭据；保存新值将替换当前会话的配置。" : "关闭服务后需重新输入，或在启动前设置环境变量。"}</span></div><div class="form-actions">${info?.source === "session" ? button("清除会话凭据", "clear-credential", "danger", `data-name="${esc(name)}"`) : ""}${button("取消", "close-modal")}<button type="submit" class="button primary">保存凭据</button></div></form>`, name);
}
function agentDialog(id = null) {
  const item = id ? S.config.agents[id] : { command: [], args: [] };
  modal(id ? `配置 ${agentName(id)}` : "添加自定义 CLI", "命令以参数数组执行，不通过 Shell 解释。", `<form id="agent-form"><div class="form-grid"><div class="field full"><label for="agent-id">适配器标识</label><input id="agent-id" name="id" value="${esc(id)}" required pattern="[A-Za-z0-9](?:[A-Za-z0-9_.]|-){0,79}" placeholder="custom-agent" ${id ? "readonly" : ""}></div><div class="field full"><label for="agent-command">命令参数数组（JSON）</label><textarea id="agent-command" name="command" required spellcheck="false" placeholder='["/path/to/cli"]'>${esc(JSON.stringify(item.command, null, 2))}</textarea><span class="field-help">第一个元素是可执行文件，后续元素是固定启动参数。</span></div>${!id || !AGENT_FORMATS[id] ? `<div class="field full"><label for="agent-args">自定义参数模板（JSON 数组）</label><textarea name="args" id="agent-args" spellcheck="false">${esc(JSON.stringify(item.args || [], null, 2))}</textarea><span class="field-help">可使用 {model}、{base_url}、{workspace}、{prompt}、{output_file}。密钥通过环境变量传入，不能放入参数。</span></div>` : ""}</div>${modalActions()}</form>`, id);
}
function deleteDialog(kind, id) {
  const label = { provider: "模型平台", model: "审阅模型", github: "GitHub 集成" }[kind];
  modal(`移除${label}`, `确认移除${id ? ` ${id}` : "当前配置"}？已保存的扫描报告会保留。`, `<form id="delete-form"><div class="form-actions">${button("取消", "close-modal")}<button class="button danger" type="submit">确认移除</button></div></form>`, { kind, id });
}
async function saveConfig(config) {
  let result;
  try { result = await api("/api/config", { method: "PUT", body: { config, revision: S.configRevision } }); }
  catch (error) {
    if (error.status === 409) throw new Error("配置已在其他页面更新，本次修改未保存。当前输入仍保留；请重新加载页面查看最新配置后再编辑。");
    throw error;
  }
  S.config = result.config; S.configRevision = result.config_revision;
  S.credentials = result.credentials || S.credentials; S.agents = result.agents || S.agents;
}
async function refreshBootstrap() {
  const data = await api("/api/bootstrap");
  S.token = data.csrf_token; S.config = data.config; S.configRevision = data.config_revision;
  S.credentials = data.credentials || []; S.agents = data.agents || []; S.jobs = data.jobs || [];
  $("#version-label").textContent = `autoreviewer v${data.version || "0.1.0"}`;
  setConnected(true);
}
async function route() {
  if (!S.config) return;
  S.routeRevision += 1;
  let hash = location.hash.slice(1) || "overview";
  const jobMatch = /^job\/([^/]+)$/.exec(hash);
  const known = new Set(["overview", "scan", "models", "agents", "github"]);
  S.route = jobMatch ? "job" : known.has(hash) ? hash : "overview";
  if (S.route !== "job") { S.job = null; S.jobId = null; S.selected.clear(); }
  const names = { overview: "任务概览", scan: "新建扫描", models: "模型与平台", agents: "CLI 管理", github: "GitHub 集成", job: "扫描详情" };
  $("#breadcrumb-current").textContent = names[S.route]; document.title = `${names[S.route]} · autoreviewer`;
  $$('[data-nav]').forEach(item => { const active = item.dataset.nav === (S.route === "job" ? "overview" : S.route); item.classList.toggle("active", active); if (active) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current"); });
  if (S.route === "job") {
    const id = decodeURIComponent(jobMatch[1]);
    if (id !== S.jobId) { S.selected.clear(); S.filters = { severity: "", model: "", text: "" }; S.expandedFindings.clear(); S.allowPartial = false; }
    S.jobId = id;
    $("#view").innerHTML = '<div class="initial-loading"><span class="spinner" aria-hidden="true"></span><p>正在读取扫描任务…</p></div>';
    try { const job = await api(`/api/jobs/${encodeURIComponent(id)}`); if (S.route !== "job" || S.jobId !== id) return; S.job = job; renderJobShell(job); if (isActive(job)) schedulePoll(300); }
    catch (error) { if (S.jobId === id) $("#view").innerHTML = heading("无法读取任务", error.message) + '<a class="button" href="#overview">返回任务概览</a>'; }
  } else ({ overview: renderOverview, scan: renderScan, models: renderModels, agents: renderAgents, github: renderGitHub })[S.route]();
}
function schedulePoll(delay = isActive(S.job) || S.jobs.some(isActive) ? 1200 : 5000) {
  window.clearTimeout(S.pollTimer);
  S.pollTimer = window.setTimeout(poll, delay);
}
async function poll() {
  if (S.polling || !S.config) return;
  S.polling = true;
  try {
    const data = await api("/api/jobs"); S.jobs = data.jobs || []; setConnected(true);
    if (S.route === "overview") updateOverview();
    if (S.route === "scan") updateScanAvailability();
    if (S.route === "job" && S.jobId) { const id = S.jobId; const job = await api(`/api/jobs/${encodeURIComponent(id)}`); if (S.route === "job" && S.jobId === id) { S.job = job; updateJob(job); } }
  } catch { setConnected(false); }
  finally { S.polling = false; schedulePoll(); }
}
async function downloadFile(path, filename) {
  const response = await api(path, { raw: true });
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement("a");
  link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function downloadReport(format) {
  const jobId = S.jobId;
  await downloadFile(`/api/jobs/${encodeURIComponent(jobId)}/report?format=${format}`, `autoreviewer-${jobId}.${format === "markdown" ? "md" : "json"}`);
}
async function importReport(file) {
  if (!file) return;
  if (S.importing) throw new Error("已有报告正在导入，请稍候。");
  if (file.size > MAX_IMPORT_BYTES) throw new Error("报告文件不能超过 32 MiB。");
  S.importing = true;
  const originRevision = S.routeRevision;
  for (const control of $$('[data-action="import-report"]')) { control.disabled = true; control.textContent = "正在导入…"; }
  try {
    let report;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
      report = JSON.parse(text);
    } catch { throw new Error("请选择有效的 UTF-8 JSON 报告文件。"); }
    if (!report || typeof report !== "object" || Array.isArray(report)) throw new Error("报告内容必须是 autoreviewer JSON 对象。");
    const job = await api("/api/reports/import", { method: "POST", body: { report, name: file.name } });
    S.jobs.unshift(job);
    if (S.routeRevision === originRevision) location.hash = `job/${encodeURIComponent(job.id)}`;
    notify("报告已导入，未启动扫描或发布 Issue。");
  } finally {
    S.importing = false;
    for (const control of $$('[data-action="import-report"]')) { control.disabled = false; control.textContent = "导入 JSON 报告"; }
  }
}
async function retryJob(mode) {
  const jobId = S.jobId;
  const originRevision = S.routeRevision;
  if (!jobId || isImported(S.job)) throw new Error("导入报告只供审阅，请手动新建扫描。");
  const job = await api(`/api/jobs/${encodeURIComponent(jobId)}/retry`, { method: "POST", body: { mode } });
  S.jobs.unshift(job);
  if (S.routeRevision === originRevision && S.jobId === jobId) location.hash = `job/${encodeURIComponent(job.id)}`;
  notify("已新建扫描任务，原任务报告保持不变。");
}
async function previewIssues() {
  if (isActive(S.job)) throw new Error("扫描仍在进行，请在任务结束后预览 Issue。");
  if (!S.selected.size) throw new Error("请先选择需要提交的发现。");
  if (S.selected.size > MAX_PREVIEW_FINDINGS) throw new Error(`每次最多预览 ${MAX_PREVIEW_FINDINGS} 条发现，请减少选择后重试。`);
  const allowPartial = $("#allow-partial")?.checked || false;
  const previewJobId = S.jobId;
  const preview = await api(`/api/jobs/${encodeURIComponent(previewJobId)}/issues/preview`, { method: "POST", body: { fingerprints: [...S.selected], allow_partial: allowPartial } });
  if (S.route !== "job" || S.jobId !== previewJobId) return;
  modal("预览 GitHub Issue", "请逐条复核。点击下方发布按钮后，会向指定仓库创建 Issue。", `<form id="publish-form"><p class="publish-target">目标仓库：<strong>${esc(preview.repository)}</strong> · ${preview.issues.length} 条 Issue</p>${preview.issues.map(issue => `<details class="issue-preview"><summary>${esc(issue.title)}</summary><pre>${esc(issue.body)}</pre></details>`).join("")}<div class="field mt"><label for="publish-confirmation">输入仓库名称以确认发布</label><input id="publish-confirmation" name="confirmation" required autocomplete="off" placeholder="${esc(preview.repository)}"><span class="field-help">${esc(preview.repository)}</span></div><div class="form-actions">${button("返回复核", "close-modal")}<button type="submit" class="button primary">${icon("github")}确认发布 ${preview.issues.length} 条 Issue</button></div></form>`);
  S.preview = { ...preview, jobId: previewJobId };
}

document.addEventListener("submit", async event => {
  const form = event.target; if (!(form instanceof HTMLFormElement)) return;
  const formId = form.getAttribute("id");
  const originRevision = S.routeRevision;
  event.preventDefault(); if (form.dataset.busy === "true") return;
  const data = new FormData(form); const get = name => String(data.get(name) || "").trim();
  const submit = $('button[type="submit"]', form); form.dataset.busy = "true"; if (submit) submit.disabled = true;
  const oldLabel = submit?.innerHTML; if (submit) submit.textContent = "正在处理…";
  try {
    if (formId === "scan-form") {
      const models = data.getAll("models"); if (!models.length) throw new Error("请至少选择一个审阅模型。");
      const payload = { target: get("target"), models, concurrency: Number(get("concurrency")), timeout_seconds: Number(get("timeout_seconds")) };
      if (get("target_type") === "github" && get("ref")) payload.ref = get("ref");
      const job = await api("/api/jobs", { method: "POST", body: payload }); S.jobs.unshift(job);
      if (form.isConnected && S.routeRevision === originRevision) location.hash = `job/${encodeURIComponent(job.id)}`;
      notify("扫描任务已启动，可在任务概览查看进度。");
    } else if (formId === "provider-form") {
      const config = clone(S.config); const id = get("id"); if (!S.modalAction && Object.hasOwn(config.providers, id)) throw new Error("平台标识已存在，请使用不同名称。");
      const provider = { base_url: get("base_url"), api_format: get("api_format") }; if (get("api_key_env")) provider.api_key_env = get("api_key_env");
      Object.defineProperty(config.providers, id, { value: provider, enumerable: true, writable: true, configurable: true });
      await saveConfig(config); await finishConfigSave(form); notify("模型平台已保存。");
    } else if (formId === "model-form") {
      const config = clone(S.config); const previous = S.modalAction; const model = { id: get("id"), model: get("model"), provider: get("provider"), agent: get("agent") };
      if (config.models.some(item => item.id === model.id && item.id !== previous)) throw new Error("实例名称已存在，请使用不同名称。");
      if (AGENT_FORMATS[model.agent] && AGENT_FORMATS[model.agent] !== config.providers[model.provider].api_format) throw new Error("所选 CLI 与平台 API 协议不匹配，请调整配置。");
      if (previous) config.models = config.models.map(item => item.id === previous ? model : item); else config.models.push(model);
      await saveConfig(config); await finishConfigSave(form); notify("审阅模型已保存。");
    } else if (formId === "credential-form") {
      const name = S.modalAction; const value = String(data.get("value") || "");
      const result = await api("/api/credentials", { method: "PUT", body: { name, value } });
      form.reset(); S.credentials = result.credentials || S.credentials; await finishConfigSave(form); notify("凭据已保存到当前服务会话。");
    } else if (formId === "agent-form") {
      const config = clone(S.config); const id = get("id"); if (!S.modalAction && Object.hasOwn(config.agents, id)) throw new Error("适配器标识已存在。");
      let command, args; try { command = JSON.parse(get("command")); args = data.has("args") ? JSON.parse(get("args") || "[]") : []; } catch { throw new Error("命令和参数需要是有效的 JSON 字符串数组。"); }
      if (!Array.isArray(command) || !command.length || !command.every(item => typeof item === "string" && item.length) || !Array.isArray(args) || !args.every(item => typeof item === "string")) throw new Error("命令需要非空字符串数组，参数需要字符串数组。");
      Object.defineProperty(config.agents, id, { value: { command, args }, enumerable: true, configurable: true, writable: true });
      await saveConfig(config); await finishConfigSave(form); notify("CLI 命令已保存并重新检测。");
    } else if (formId === "github-form") {
      const config = clone(S.config); config.github = { repository: get("repository"), token_env: get("token_env"), labels: get("labels").split(",").map(value => value.trim()).filter(Boolean) };
      await saveConfig(config); await finishConfigSave(form); notify("GitHub 仓库配置已保存。");
    } else if (formId === "delete-form") {
      const config = clone(S.config); const { kind, id } = S.modalAction;
      if (kind === "provider") { if (config.models.some(model => model.provider === id)) throw new Error("仍有模型使用此平台，请先修改或移除这些模型。"); delete config.providers[id]; }
      if (kind === "model") { if (config.models.length <= 1) throw new Error("至少需要保留一个审阅模型，可编辑现有模型替换配置。"); config.models = config.models.filter(model => model.id !== id); }
      if (kind === "github") delete config.github;
      await saveConfig(config); await finishConfigSave(form); notify("配置已移除。");
    } else if (formId === "publish-form") {
      const preview = S.preview; if (!preview) throw new Error("预览已失效，请重新预览。");
      if (get("confirmation") !== preview.repository) throw new Error("输入的仓库名称与预览目标不一致。");
      const result = await api(`/api/jobs/${encodeURIComponent(preview.jobId)}/issues/publish`, { method: "POST", body: { preview_id: preview.preview_id, confirmation: get("confirmation") } });
      modal("GitHub 提交结果", `仓库 ${result.repository}`, `${(result.issues || []).map(issue => { let url = ""; try { const parsed = new URL(issue.url || issue.html_url || ""); if (parsed.protocol === "https:" && parsed.hostname === "github.com") url = parsed.href; } catch { /* Never render unsafe external links. */ } return `<div class="publish-result">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(issue.title || issue.url || issue.html_url || "查看 Issue")} ↗</a>` : esc(issue.title || issue.status || "已处理")} ${issue.status ? `<span class="tag">${esc(issue.status)}</span>` : ""}</div>`; }).join("")}<div class="form-actions">${button("完成", "close-modal", "primary")}</div>`); S.preview = null; notify("GitHub Issue 操作已完成，请查看提交结果。");
    }
  } catch (error) { if ($("#modal").open && form.closest("dialog")) modalError(error.message); else notify(error.message, "error"); }
  finally { form.dataset.busy = "false"; if (submit && submit.isConnected) { submit.disabled = false; submit.innerHTML = oldLabel; } if (formId === "scan-form") updateScanAvailability(); }
});

document.addEventListener("click", async event => {
  if (event.target.closest(".skip-link")) {
    event.preventDefault();
    $("#main-content").focus({ preventScroll: true });
    $("#main-content").scrollIntoView({ block: "start" });
    return;
  }
  const control = event.target.closest("[data-action]"); if (!control || control.disabled) return;
  const action = control.dataset.action; const id = control.dataset.id;
  try {
    if (action === "close-modal") { closeModal(); return; }
    if (action === "add-provider") { providerDialog(); return; }
    if (action === "edit-provider") { providerDialog(id); return; }
    if (action === "add-model") { modelDialog(); return; }
    if (action === "edit-model") { modelDialog(id); return; }
    if (action === "credential") { credentialDialog(control.dataset.name); return; }
    if (action === "edit-agent") { agentDialog(id); return; }
    if (action === "add-agent") { agentDialog(); return; }
    if (action === "delete-provider") { deleteDialog("provider", id); return; }
    if (action === "delete-model") { deleteDialog("model", id); return; }
    if (action === "delete-github") { deleteDialog("github"); return; }
    if (action === "import-report") { $("#import-report-file").value = ""; $("#import-report-file").click(); return; }
    control.disabled = true;
    if (action === "clear-credential") { const form = control.closest("form"); const result = await api("/api/credentials", { method: "PUT", body: { name: control.dataset.name, value: "" } }); S.credentials = result.credentials || S.credentials; await finishConfigSave(form); notify("当前会话凭据已清除；已有环境变量仍可继续使用。"); }
    if (action === "cancel-job") { const idToCancel = S.jobId; const job = await api(`/api/jobs/${encodeURIComponent(idToCancel)}/cancel`, { method: "POST", body: {} }); if (S.jobId === idToCancel) { S.job = job; updateJob(job); } notify("已请求停止扫描，正在清理运行中的实例。"); }
    if (action === "download-json") await downloadReport("json");
    if (action === "download-markdown") await downloadReport("markdown");
    if (action === "export-config") await downloadFile("/api/config/export", "autoreviewer.toml");
    if (action === "retry-failed") await retryJob("failed");
    if (action === "retry-all") await retryJob("all");
    if (action === "preview-issues") await previewIssues();
    if (action === "retry-bootstrap") { await start(); }
  } catch (error) { if ($("#modal").open && control.closest("dialog")) modalError(error.message); else notify(error.message, "error"); }
  finally { if (control.isConnected) control.disabled = false; }
});
document.addEventListener("change", event => {
  const target = event.target;
  if (target.name === "target_type") { const remote = target.value === "github"; $("#target-label").textContent = remote ? "GitHub 仓库地址 *" : "代码目录 *"; $("#scan-target").placeholder = remote ? "https://github.com/owner/repository" : "/path/to/your/project"; $("#target-help").textContent = remote ? "支持 GitHub HTTPS 仓库；私有仓库需配置对应 GitHub Token。" : "填写运行 autoreviewer 服务的机器上的目录路径。"; $("#ref-field").hidden = !remote; $("#scan-ref").disabled = !remote; }
  if (target.id === "model-provider" || target.id === "model-agent") showCompatibility();
  if (target.id === "finding-severity") { S.filters.severity = target.value; renderFindings(); }
  if (target.id === "finding-model") { S.filters.model = target.value; renderFindings(); }
  if (target.id === "group-related") { S.groupRelated = target.checked; renderFindings(); }
  if (target.id === "allow-partial") S.allowPartial = target.checked;
  if (target.id === "select-visible") { for (const item of visibleFindings()) { if (target.checked) S.selected.add(item.fingerprint); else S.selected.delete(item.fingerprint); } renderFindings(); }
  if (target.dataset.fingerprint) { if (target.checked) S.selected.add(target.dataset.fingerprint); else S.selected.delete(target.dataset.fingerprint); updateSelection(); }
});
document.addEventListener("input", event => { if (event.target.id === "finding-text") { S.filters.text = event.target.value; renderFindings(); } });
$("#modal").addEventListener("cancel", () => { $("#modal-content").replaceChildren(); S.modalAction = null; S.preview = null; });
$("#import-report-file").addEventListener("change", event => {
  const input = event.currentTarget;
  importReport(input.files[0]).catch(error => notify(error.message, "error")).finally(() => { input.value = ""; });
});
window.addEventListener("hashchange", () => { closeModal(); route().catch(error => notify(error.message, "error")); });
async function start() {
  try { await refreshBootstrap(); await route(); schedulePoll(isActive(S.job) ? 300 : 1200); }
  catch (error) { setConnected(false); $("#view").innerHTML = heading("工作台暂时无法连接", error.message) + button(icon("refresh") + "重新连接", "retry-bootstrap", "primary"); }
}
start();
