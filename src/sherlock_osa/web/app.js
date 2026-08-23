"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { deploymentMode: "UNKNOWN", lastBundle: null };

function toast(message, error = false) {
  const element = $("#toast");
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.setTimeout(() => { element.hidden = true; }, 5000);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: { code: "INVALID_RESPONSE", message: "Niepoprawna odpowiedź API" },
  }));
  if (!response.ok) {
    const error = new Error(body.error?.message || `HTTP ${response.status}`);
    error.code = body.error?.code || "HTTP_ERROR";
    throw error;
  }
  return body;
}

function field(form, name) {
  const control = form.elements.namedItem(name);
  return control ? control.value.trim() : "";
}

function searchRequest(form) {
  const kind = field(form, "search_kind");
  const query = field(form, "query");
  if (!query) {
    const error = new Error("Wpisz wartość do wyszukania.");
    error.code = "SEARCH_QUERY_REQUIRED";
    throw error;
  }
  return { kind, query };
}

function renderSearchResult(bundle) {
  const research = bundle.research || {};
  const facts = [
    ["STATUS", research.status || "UNKNOWN"],
    ["IDENTIFIERS", String(research.identifiers_seen ?? "UNKNOWN")],
    ["EVIDENCE", String(research.evidence?.length ?? "UNKNOWN")],
    ["TAINTED", String(research.tainted_evidence ?? "UNKNOWN")],
    ["STOP", research.stop_reason || "UNKNOWN"],
    ["ENGINE", bundle.truth?.external_engine_called === false ? "SHERLOCK LOCAL" : "UNKNOWN"],
  ];
  const panel = $("#search-result");
  const grid = $("#search-result-grid");
  if (!panel || !grid) return;
  grid.replaceChildren(...facts.map(([label, value]) => {
    const article = document.createElement("article");
    const span = document.createElement("span");
    const strong = document.createElement("strong");
    span.textContent = label;
    strong.textContent = value;
    article.append(span, strong);
    return article;
  }));
  $("#search-result-json").textContent = JSON.stringify(bundle, null, 2);
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runSearch(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#search-submit");
  button.disabled = true;
  button.textContent = "SEARCH → SOURCES → CORRELATE…";
  try {
    const request = searchRequest(form);
    const bundle = await api("/api/v1/search", {
      method: "POST",
      body: JSON.stringify(request),
    });
    state.lastBundle = bundle;
    renderSearchResult(bundle);
    toast(
      `Gotowe // evidence ${bundle.research?.evidence?.length ?? 0} // identifiers ${bundle.research?.identifiers_seen ?? 0}`,
    );
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = "SZUKAJ → CORRELATE → EVIDENCE";
  }
}

function updateSearchMode() {
  const form = $("#search-form");
  if (!form) return;
  const kind = field(form, "search_kind");
  const input = $("#search-query");
  const note = $("#search-note");
  const config = {
    EMAIL: ["name@example.com", "Email → Holehe + username/domain pivots + passive domain sources."],
    USERNAME: ["username", "Nick → Maigret + profile/URL pivots + correlation."],
    PERSON: ["Jan Kowalski", "Imię + nazwisko → bounded kandydaci username → ten sam research engine."],
  }[kind] || ["Wpisz ślad", "Bounded passive research."];
  input.placeholder = config[0];
  note.textContent = config[1];
}

function configureStandalone(health) {
  const searchKeyField = $("#search-api-key-field");
  if (searchKeyField) searchKeyField.hidden = true;
  const searchKey = $("#search-api-key");
  if (searchKey) searchKey.required = false;
  for (const control of $("#search-form").elements) control.disabled = false;

  const sandbox = $("#mission");
  if (sandbox) sandbox.hidden = true;
  const sandboxResult = $("#result");
  if (sandboxResult) sandboxResult.hidden = true;

  const deployment = $("#deployment-mode");
  if (deployment) {
    deployment.classList.add("online");
    deployment.innerHTML = "<i></i> SHERLOCK LOCAL";
  }

  const sources = health.research?.sources || [];
  const ready = sources.filter((source) => source.available && source.version_match).length;
  toast(`Sherlock standalone online // źródła gotowe ${ready}/${sources.length}`);
  updateSearchMode();
}

async function loadStatus() {
  try {
    const health = await api("/api/v1/health");
    state.deploymentMode = health.deployment_mode || "UNKNOWN";
    const status = $("#service-status");
    if (status) {
      status.classList.add("online");
      status.innerHTML = "<i></i> API ONLINE";
    }
    if (state.deploymentMode === "STANDALONE_RESEARCH") configureStandalone(health);
  } catch (error) {
    const status = $("#service-status");
    if (status) status.textContent = "API OFFLINE";
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  }
}

async function loadReferences() {
  try {
    const result = await api("/api/v1/reference-repos");
    const repos = result.repositories || [];
    const count = $("#repo-count");
    if (count) count.textContent = `${repos.length} REPO // SNAPSHOT ${result.captured_at?.slice(0, 10) || "UNKNOWN"}`;
    const cards = repos.map((repo) => {
      const card = document.createElement("article");
      card.className = "repo";
      const link = document.createElement("a");
      link.href = repo.url;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = repo.name;
      const description = document.createElement("p");
      description.textContent = repo.pattern;
      const meta = document.createElement("div");
      meta.className = "repo-meta";
      const plane = document.createElement("span");
      const license = document.createElement("b");
      plane.textContent = repo.plane;
      license.textContent = repo.license;
      meta.append(plane, license);
      card.append(link, description, meta);
      return card;
    });
    $("#repo-grid")?.replaceChildren(...cards);
  } catch {
    const count = $("#repo-count");
    if (count) count.textContent = "BENCHMARK UNAVAILABLE";
  }
}

$("#search-form").addEventListener("submit", runSearch);
$("#search-kind").addEventListener("change", updateSearchMode);
updateSearchMode();
loadStatus();
loadReferences();
