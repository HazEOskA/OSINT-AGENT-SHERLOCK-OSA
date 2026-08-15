"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {
  deploymentMode: "UNKNOWN",
  capabilities: null,
  lastResult: null,
  progressTimer: null,
  progressStarted: 0,
};

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.clearTimeout(element.dismissTimer);
  element.dismissTimer = window.setTimeout(() => { element.hidden = true; }, 6000);
}

function token() {
  const value = $("#api-key").value.trim();
  if (value) sessionStorage.setItem("sherlock_api_key", value);
  return value || sessionStorage.getItem("sherlock_api_key") || "";
}

async function api(path, options = {}, auth = false) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (auth) headers.Authorization = `Bearer ${token()}`;
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: { code: "INVALID_RESPONSE", message: "Źródło zwróciło niepoprawną odpowiedź." },
  }));
  if (!response.ok) {
    const error = new Error(body.error?.message || `HTTP ${response.status}`);
    error.code = body.error?.code || "HTTP_ERROR";
    throw error;
  }
  return body;
}

function field(form, name) {
  const element = form.elements.namedItem(name);
  return element ? String(element.value).trim() : "";
}

function investigationPayload(form) {
  return {
    query: field(form, "query"),
    kind: field(form, "kind"),
    default_region: field(form, "default_region"),
    purpose: field(form, "purpose"),
    include_darkweb: form.elements.namedItem("include_darkweb").checked,
    consent: form.elements.namedItem("consent").checked,
  };
}

function startProgress() {
  const progress = $("#agent-progress");
  const labels = [
    "Resolver dobiera skille…",
    "Uruchamiam źródła pasywne…",
    "Sprawdzam indeks dark web…",
    "Koreluję ustalenia i kandydatów…",
    "Buduję evidence ledger…",
  ];
  progress.hidden = false;
  state.progressStarted = performance.now();
  let index = 0;
  const update = () => {
    const elapsed = (performance.now() - state.progressStarted) / 1000;
    $("#progress-time").textContent = `${elapsed.toFixed(1).padStart(4, "0")}s`;
    index = Math.min(labels.length - 1, Math.floor(elapsed / 1.7));
    $("#progress-label").textContent = labels[index];
    document.querySelectorAll(".progress-steps span").forEach((item, itemIndex) => {
      item.classList.toggle("active", itemIndex <= index);
    });
  };
  update();
  state.progressTimer = window.setInterval(update, 100);
}

function stopProgress() {
  window.clearInterval(state.progressTimer);
  state.progressTimer = null;
  $("#agent-progress").hidden = true;
}

function textElement(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = String(value ?? "");
  return element;
}

function externalLink(label, url, className = "") {
  const link = textElement("a", className, label);
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function renderSummary(summary) {
  const items = [
    ["USTALENIA", summary.finding_count ?? 0],
    ["ŹRÓDŁA WYCIEKU", summary.breach_source_count ?? 0],
    ["DARK WEB MATCH", summary.darkweb_match_count ?? summary.darkweb_index_match_count ?? 0],
    ["LIVE CONFIRMED", summary.live_confirmed_count ?? 0],
    ["ŹRÓDŁA ZAKOŃCZONE", summary.sources_completed ?? 0],
  ];
  $("#summary-grid").replaceChildren(...items.map(([label, value]) => {
    const card = document.createElement("article");
    card.append(textElement("span", "", label), textElement("strong", "", value));
    return card;
  }));
}

function metadataLabels(metadata) {
  if (!metadata || typeof metadata !== "object") return [];
  const priority = ["country", "region", "calling_code", "public_repos", "created_at", "entity_id"];
  const keys = [...priority, ...Object.keys(metadata)].filter((value, index, array) => array.indexOf(value) === index);
  return keys.flatMap((key) => {
    const value = metadata[key];
    if (value === null || value === undefined || value === "" || typeof value === "object") return [];
    return [`${key}: ${value}`];
  }).slice(0, 5);
}

function renderFindings(findings) {
  $("#finding-count").textContent = `${findings.length}`;
  if (!findings.length) {
    $("#finding-list").replaceChildren(textElement(
      "p",
      "empty-state",
      "Brak potwierdzonych ustaleń z dostępnych źródeł. To nie jest dowód braku ekspozycji — sprawdź status adapterów w trace.",
    ));
    return;
  }
  const initials = {
    BREACH_EXPOSURE: "BR",
    DARKWEB_INDEX_MATCH: "DW",
    DARKWEB_CONTENT_MATCH: "TOR",
    PUBLIC_PROFILE: "ID",
    PERSON_CANDIDATE: "?",
    PHONE_METADATA: "TEL",
    DNS_ADDRESS: "DNS",
    REVERSE_DNS: "PTR",
    RDAP_RECORD: "RD",
  };
  const nodes = findings.map((finding) => {
    const article = document.createElement("article");
    article.className = "finding";
    article.append(textElement("span", "finding-icon", initials[finding.category] || "OS"));
    const main = document.createElement("div");
    main.className = "finding-main";
    main.append(textElement("h4", "", finding.title), textElement("p", "", finding.value));
    const meta = document.createElement("div");
    meta.className = "finding-meta";
    const labels = [
      finding.source,
      finding.verification,
      `confidence: ${finding.confidence}`,
      ...metadataLabels(finding.metadata),
    ];
    meta.replaceChildren(...labels.map((label) => textElement("span", "", label)));
    main.append(meta);
    article.append(main);
    if (finding.source_url) article.append(externalLink("ŹRÓDŁO ↗", finding.source_url, "finding-link"));
    return article;
  });
  $("#finding-list").replaceChildren(...nodes);
}

function renderPivots(pivots) {
  $("#pivot-count").textContent = `${pivots.length}`;
  if (!pivots.length) {
    $("#pivot-list").replaceChildren(textElement("p", "empty-state", "Brak dodatkowych pivotów dla tego typu zapytania."));
    return;
  }
  const nodes = pivots.map((pivot) => {
    const link = externalLink("", pivot.url, "pivot");
    link.append(textElement("span", "", pivot.label), textElement("b", "", "↗"));
    return link;
  });
  $("#pivot-list").replaceChildren(...nodes);
}

function renderTrace(trace) {
  const uniqueSkills = new Set(trace.map((entry) => entry.skill_id));
  $("#skill-count").textContent = `${uniqueSkills.size} SKILLS`;
  const nodes = trace.map((entry) => {
    const item = document.createElement("li");
    const line = document.createElement("div");
    line.className = "trace-line";
    line.append(textElement("b", "", entry.skill_id));
    line.append(textElement("span", `trace-status ${String(entry.status).toLowerCase()}`, entry.status));
    item.append(line);
    item.append(textElement("p", "", entry.message));
    item.append(textElement(
      "small",
      "",
      `${entry.adapter_id} // ${entry.duration_ms ?? 0}ms // network=${String(Boolean(entry.network_effect)).toUpperCase()}`,
    ));
    return item;
  });
  $("#trace-list").replaceChildren(...nodes);
}

function renderResult(result) {
  state.lastResult = result;
  const query = result.query || {};
  const summary = result.summary || {};
  $("#result-title").textContent = `${query.kind || "QUERY"}: ${query.masked || "—"}`;
  $("#result-subtitle").textContent = `ID ${result.investigation_id} // ${result.deployment_mode} // ${result.created_at}`;
  const risk = String(summary.risk || "UNKNOWN");
  const riskBadge = $("#risk-badge");
  riskBadge.className = `risk-badge ${risk.toLowerCase()}`;
  riskBadge.querySelector("b").textContent = risk;
  renderSummary(summary);
  renderFindings(result.findings || []);
  renderPivots(result.pivots || []);
  renderTrace(result.execution_trace || []);
  const verification = result.evidence?.verification || {};
  $("#ledger-status").textContent = verification.valid ? `VALID // ${verification.record_count}` : "INVALID";
  $("#evidence-json").textContent = JSON.stringify({
    verification,
    records: result.evidence?.records || [],
    truth: result.truth || {},
  }, null, 2);
  $("#result").hidden = false;
  $("#result").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runInvestigation(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#submit-search");
  button.disabled = true;
  button.querySelector("span").textContent = "AGENT PRACUJE…";
  startProgress();
  try {
    const result = await api(
      "/api/v1/osint/investigate",
      { method: "POST", body: JSON.stringify(investigationPayload(form)) },
      state.deploymentMode === "PRIVATE_CONTROL_PLANE",
    );
    renderResult(result);
    toast(`Gotowe: ${result.summary.finding_count} ustaleń, ledger ${result.evidence.verification.valid ? "VALID" : "INVALID"}.`);
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  } finally {
    stopProgress();
    button.disabled = false;
    button.querySelector("span").textContent = "URUCHOM AGENTA";
  }
}

function renderSkills(capabilities) {
  const skills = capabilities.skills || [];
  $("#skills-status").textContent = `${skills.length} SKILLS // ${capabilities.registry || "REGISTRY"}`;
  const cards = skills.map((skill) => {
    const card = document.createElement("article");
    card.className = "skill-card";
    const top = document.createElement("div");
    top.className = "skill-top";
    top.append(textElement("code", "", skill.id), textElement("span", "", skill.effect));
    card.append(top, textElement("h3", "", skill.title), textElement("p", "", skill.description));
    const adapters = document.createElement("div");
    adapters.className = "skill-adapters";
    adapters.replaceChildren(...(skill.adapters || []).map((adapter) => textElement("span", "", adapter)));
    card.append(adapters);
    return card;
  });
  $("#skill-grid").replaceChildren(...cards);
  const leakcheck = capabilities.providers?.["leakcheck.v2"];
  if (leakcheck === "READY") {
    const source = $("#leakcheck-source");
    source.querySelector(".source-dot").className = "source-dot live";
    source.querySelector("small").textContent = "telefon / wycieki — ready";
  }
}

async function loadStatusAndSkills() {
  try {
    const [health, capabilities] = await Promise.all([
      api("/api/v1/health"),
      api("/api/v1/osint/capabilities"),
    ]);
    state.deploymentMode = health.deployment_mode || "UNKNOWN";
    state.capabilities = capabilities;
    const status = $("#service-status");
    status.classList.add("online");
    status.replaceChildren(document.createElement("i"), document.createTextNode(" ONLINE"));
    $("#deployment-mode").textContent = state.deploymentMode === "PUBLIC_PASSIVE_OSINT" ? "PUBLIC PASSIVE" : "PRIVATE OSA";
    const privateRuntime = state.deploymentMode === "PRIVATE_CONTROL_PLANE";
    $("#api-key-field").hidden = !privateRuntime;
    $("#api-key").required = privateRuntime;
    renderSkills(capabilities);
  } catch (error) {
    $("#service-status").textContent = "API OFFLINE";
    $("#skills-status").textContent = "REGISTRY UNAVAILABLE";
  }
}

async function loadReferences() {
  try {
    const result = await api("/api/v1/reference-repos");
    const repos = result.repositories || [];
    $("#repo-count").textContent = `${repos.length} REPO // ${String(result.captured_at || "").slice(0, 10)}`;
    const cards = repos.map((repo) => {
      const card = document.createElement("article");
      card.className = "repo";
      card.append(externalLink(repo.name, repo.url));
      card.append(textElement("p", "", repo.pattern));
      const meta = document.createElement("div");
      meta.className = "repo-meta";
      meta.append(textElement("span", "", repo.plane), textElement("b", "", repo.license));
      card.append(meta);
      return card;
    });
    $("#repo-grid").replaceChildren(...cards);
  } catch {
    $("#repo-count").textContent = "BENCHMARK UNAVAILABLE";
  }
}

const placeholders = {
  AUTO: "email@domena.pl, +48 500 000 000, Jan Kowalski…",
  EMAIL: "nazwa@domena.pl",
  PHONE: "+48 500 000 000",
  PERSON: "Jan Kowalski",
  USERNAME: "username",
  DOMAIN: "domena.pl",
  IP: "203.0.113.10",
};

$("#query-kind").addEventListener("change", (event) => {
  $("#query-input").placeholder = placeholders[event.target.value] || placeholders.AUTO;
});
$("#osint-form").addEventListener("submit", runInvestigation);
const savedToken = sessionStorage.getItem("sherlock_api_key");
if (savedToken) $("#api-key").value = savedToken;
loadStatusAndSkills();
loadReferences();
