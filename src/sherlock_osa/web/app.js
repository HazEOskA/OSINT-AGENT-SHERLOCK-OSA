"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { lastMission: null, lastDecision: null };

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.setTimeout(() => { element.hidden = true; }, 5000);
}

function token() {
  const value = $("#api-key").value.trim();
  if (value) sessionStorage.setItem("sherlock_api_key", value);
  return value || sessionStorage.getItem("sherlock_api_key") || "";
}

async function api(path, options = {}, auth = true) {
  const headers = { "Accept": "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (auth) headers.Authorization = `Bearer ${token()}`;
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({ error: { code: "INVALID_RESPONSE", message: "Niepoprawna odpowiedź API" } }));
  if (!response.ok) {
    const error = new Error(body.error?.message || `HTTP ${response.status}`);
    error.code = body.error?.code || "HTTP_ERROR";
    throw error;
  }
  return body;
}

function field(form, name) { return form.elements.namedItem(name).value.trim(); }

function missionPayload(form) {
  const mode = field(form, "mode");
  const portRaw = field(form, "port");
  const ports = portRaw && mode !== "RESEARCH_PASSIVE" ? [Number(portRaw)] : [];
  return {
    goal: field(form, "goal"),
    mode,
    targets: [{ kind: field(form, "target_kind"), value: field(form, "target_value"), ports }],
    allowed_capabilities: [field(form, "capability")],
    ttl_minutes: Number(field(form, "ttl_minutes")),
    operator_id: field(form, "operator_id"),
  };
}

function routeFor(mode) {
  return {
    LAB_RANGE: "range-only",
    RESEARCH_PASSIVE: "research-passive",
    AUTHORIZED_EXTERNAL: "external-allowlist",
  }[mode];
}

function renderResult(bundle) {
  const panel = $("#result");
  const mission = bundle.mission?.mission || {};
  const decision = bundle.decision?.decision || {};
  const receipt = bundle.execution?.receipt || {};
  const replay = bundle.replay || {};
  const facts = [
    ["ENGINE", mission.engine_state || "UNKNOWN"],
    ["POLICY", decision.effect || "UNKNOWN"],
    ["NETWORK EFFECT", String(receipt.network_effect_performed ?? "UNKNOWN").toUpperCase()],
    ["REPLAY", replay.valid === true ? "VALID" : "UNKNOWN"],
  ];
  const grid = $("#result-grid");
  grid.replaceChildren(...facts.map(([label, value]) => {
    const article = document.createElement("article");
    const span = document.createElement("span");
    const strong = document.createElement("strong");
    span.textContent = label;
    strong.textContent = value;
    article.append(span, strong);
    return article;
  }));
  $("#result-json").textContent = JSON.stringify(bundle, null, 2);
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runFlow(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  button.textContent = "WYKONYWANIE KONTROLOWANEGO FLOW…";
  try {
    const payload = missionPayload(form);
    const missionResponse = await api("/api/v1/missions", { method: "POST", body: JSON.stringify(payload) });
    const mission = missionResponse.mission;
    state.lastMission = mission;
    const capability = payload.allowed_capabilities[0];
    const needsPort = ["lab.http.probe", "lab.network.scan", "external.http.probe", "external.network.scan"].includes(capability);
    const decisionPayload = {
      mission_id: mission.mission_id,
      capability,
      target: payload.targets[0],
      route: routeFor(payload.mode),
      port: needsPort ? payload.targets[0].ports[0] : null,
      request_id: crypto.randomUUID(),
    };
    const decisionResponse = await api("/api/v1/decisions", { method: "POST", body: JSON.stringify(decisionPayload) });
    state.lastDecision = decisionResponse.decision;
    let executionResponse = { receipt: { status: "NOT_EXECUTED" } };
    if (decisionResponse.decision.effect === "ALLOW") {
      executionResponse = await api("/api/v1/executions/simulate", {
        method: "POST",
        body: JSON.stringify({ decision_id: decisionResponse.decision.decision_id }),
      });
    }
    const replayResponse = await api(`/api/v1/missions/${mission.mission_id}/replay`, {
      method: "POST", body: "{}",
    });
    renderResult({ mission: missionResponse, decision: decisionResponse, execution: executionResponse, replay: replayResponse });
    toast("Flow zakończony. Sprawdź receipt i replay.");
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = "ENGINE → SIGN → DECIDE → SIMULATE";
  }
}

async function loadStatus() {
  try {
    const health = await api("/api/v1/health", {}, false);
    const status = $("#service-status");
    status.classList.add("online");
    status.innerHTML = "<i></i> API ONLINE";
    if (health.status !== "OK") status.textContent = `API ${health.status}`;
  } catch {
    $("#service-status").textContent = "API OFFLINE";
  }
}

async function loadReferences() {
  try {
    const result = await api("/api/v1/reference-repos", {}, false);
    const repos = result.repositories || [];
    $("#repo-count").textContent = `${repos.length} REPO // SNAPSHOT ${result.captured_at.slice(0, 10)}`;
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
    $("#repo-grid").replaceChildren(...cards);
  } catch (error) {
    $("#repo-count").textContent = "BENCHMARK UNAVAILABLE";
  }
}

async function verifyLedger() {
  try {
    const result = await api("/api/v1/evidence/verify");
    toast(result.valid ? `Ledger VALID // ${result.record_count} rekordów // ${result.head_hash.slice(0, 12)}…` : `Ledger INVALID: ${result.errors.join(", ")}`, !result.valid);
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  }
}

const savedToken = sessionStorage.getItem("sherlock_api_key");
if (savedToken) $("#api-key").value = savedToken;
$("#mission-form").addEventListener("submit", runFlow);
$("#verify-ledger").addEventListener("click", verifyLedger);
loadStatus();
loadReferences();
