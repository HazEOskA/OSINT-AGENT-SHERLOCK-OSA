"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {
  deploymentMode: "UNKNOWN",
  lastMission: null,
  lastDecision: null,
  lastBundle: null,
};

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
  const isPublicReplay = bundle.deployment_mode === "PUBLIC_REPLAY_DEMO";
  const facts = [
    ["ENGINE", isPublicReplay ? "REPLAY VECTOR" : (mission.engine_state || "UNKNOWN")],
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
  button.textContent = state.deploymentMode === "PUBLIC_REPLAY_DEMO"
    ? "WERYFIKACJA PUBLICZNEGO REPLAYU…"
    : "WYKONYWANIE KONTROLOWANEGO FLOW…";
  try {
    const payload = missionPayload(form);
    if (state.deploymentMode === "PUBLIC_REPLAY_DEMO") {
      const bundle = await api(
        "/api/v1/demo/replay",
        { method: "POST", body: JSON.stringify(payload) },
        false,
      );
      state.lastBundle = bundle;
      renderResult(bundle);
      toast("Replay VALID. Live Engine i efekty sieciowe nie zostały uruchomione.");
      return;
    }
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
    const bundle = { mission: missionResponse, decision: decisionResponse, execution: executionResponse, replay: replayResponse };
    state.lastBundle = bundle;
    renderResult(bundle);
    toast("Flow zakończony. Sprawdź receipt i replay.");
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = state.deploymentMode === "PUBLIC_REPLAY_DEMO"
      ? "REPLAY VECTOR → BROKER → EVIDENCE"
      : "ENGINE → SIGN → DECIDE → SIMULATE";
  }
}

function configurePublicReplay() {
  const apiKeyField = $("#api-key-field");
  const apiKey = $("#api-key");
  apiKeyField.hidden = true;
  apiKey.required = false;

  const form = $("#mission-form");
  const mode = form.elements.namedItem("mode");
  const targetKind = form.elements.namedItem("target_kind");
  const ttl = form.elements.namedItem("ttl_minutes");
  mode.value = "LAB_RANGE";
  mode.disabled = true;
  targetKind.value = "LAB_ASSET";
  targetKind.disabled = true;
  ttl.max = "60";
  if (Number(ttl.value) > 60) ttl.value = "30";

  $("#deployment-mode").classList.add("online");
  $("#deployment-mode").innerHTML = "<i></i> PUBLIC REPLAY";
  $("#mission-intro").textContent =
    "Publiczny deploy odtwarza jawnie oznaczony wektor receiptu OSA przez prawdziwy podpis, broker, worker symulacyjny i hash-chain. Nie wywołuje live Engine, sieci ani shella.";
  $("#submit-flow").textContent = "REPLAY VECTOR → BROKER → EVIDENCE";
  $("#form-note").textContent =
    "Tryb publiczny jest stateless i LAB-only. Nowe misje wykonawcze wymagają prywatnego runtime połączonego z OSA Engine.";
}

async function loadStatus() {
  try {
    const health = await api("/api/v1/health", {}, false);
    state.deploymentMode = health.deployment_mode || "PRIVATE_CONTROL_PLANE";
    const status = $("#service-status");
    status.classList.add("online");
    status.innerHTML = state.deploymentMode === "PUBLIC_REPLAY_DEMO"
      ? "<i></i> DEMO ONLINE"
      : "<i></i> API ONLINE";
    if (state.deploymentMode === "PUBLIC_REPLAY_DEMO") configurePublicReplay();
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
  if (state.deploymentMode === "PUBLIC_REPLAY_DEMO") {
    const verification = state.lastBundle?.evidence?.verification;
    if (!verification) {
      toast("Najpierw uruchom publiczny replay — ledger powstaje i jest sprawdzany per request.");
      return;
    }
    toast(
      verification.valid
        ? `Ledger VALID // ${verification.record_count} rekordów // ${verification.head_hash.slice(0, 12)}…`
        : `Ledger INVALID: ${(verification.errors || []).join(", ")}`,
      !verification.valid,
    );
    return;
  }
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
