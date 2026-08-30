"use strict";

const $ = (selector) => document.querySelector(selector);

const state = {
  deploymentMode: "UNKNOWN",
};

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.setTimeout(() => { element.hidden = true; }, 5000);
}

function operatorToken() {
  const input = $("#api-key");
  const value = input?.value.trim() || sessionStorage.getItem("sherlock_api_key") || "";
  if (value) sessionStorage.setItem("sherlock_api_key", value);
  return value;
}

async function requestJson(path, options = {}, withAuth = false) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (withAuth) headers.Authorization = `Bearer ${operatorToken()}`;

  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: { code: "INVALID_RESPONSE", message: "Backend zwrócił niepoprawny JSON." },
  }));

  if (!response.ok) {
    const error = new Error(body.error?.message || `HTTP ${response.status}`);
    error.code = body.error?.code || "HTTP_ERROR";
    error.status = response.status;
    throw error;
  }
  return body;
}

function compact(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(compact).filter(Boolean).slice(0, 4).join(" · ");
  }
  if (typeof value === "object") {
    const preferred = [
      "platform", "site", "service", "name", "username", "url", "domain",
      "breach", "title", "date", "status", "source", "message",
    ];
    const parts = [];
    for (const key of preferred) {
      if (value[key] !== undefined && value[key] !== null) {
        const rendered = compact(value[key]);
        if (rendered) parts.push(`${key}: ${rendered}`);
      }
    }
    if (parts.length) return parts.slice(0, 4).join(" · ");
    return Object.entries(value)
      .slice(0, 4)
      .map(([key, item]) => `${key}: ${compact(item)}`)
      .join(" · ");
  }
  return String(value);
}

function renderList(selector, items, emptyText) {
  const container = $(selector);
  container.replaceChildren();

  if (!items?.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent = emptyText;
    container.append(empty);
    return;
  }

  for (const item of items) {
    const article = document.createElement("article");
    article.className = "signal-item";
    const text = document.createElement("p");
    text.textContent = compact(item) || "Znaleziono sygnał.";
    article.append(text);
    container.append(article);
  }
}

function renderActions(actions) {
  const container = $("#actions-list");
  container.replaceChildren();

  for (const action of actions || []) {
    const article = document.createElement("article");
    article.className = "action-item";

    const head = document.createElement("div");
    const priority = document.createElement("span");
    priority.className = `priority priority-${String(action.priority || "baseline").toLowerCase()}`;
    priority.textContent = action.priority || "ACTION";
    const title = document.createElement("strong");
    title.textContent = action.title || "Działanie";
    head.append(priority, title);

    const reason = document.createElement("p");
    reason.textContent = action.reason || "";

    const list = document.createElement("ol");
    for (const step of action.steps || []) {
      const li = document.createElement("li");
      li.textContent = step;
      list.append(li);
    }

    article.append(head, reason, list);
    container.append(article);
  }
}

function renderResult(bundle) {
  const exposure = bundle.exposure || {};
  const identity = bundle.identity || {};
  const risk = bundle.risk || {};
  const counts = exposure.counts || {};
  const level = String(risk.level || "unknown").toUpperCase();

  $("#result-title").textContent = bundle.query?.value || "Twój cyfrowy ślad";
  $("#risk-badge").textContent = level;
  $("#risk-badge").dataset.level = level.toLowerCase();
  $("#ai-summary").textContent = identity.summary || "Provider nie zwrócił podsumowania AI.";
  $("#accounts-count").textContent = String(counts.linked_accounts ?? identity.linked_accounts?.length ?? 0);
  $("#breaches-count").textContent = String(counts.breaches ?? exposure.breaches?.length ?? 0);
  $("#stealer-count").textContent = String(counts.infostealer ?? exposure.infostealer?.length ?? 0);

  renderList("#accounts-list", identity.linked_accounts || [], "Brak połączonych kont w odpowiedzi.");
  renderList("#breaches-list", exposure.breaches || [], "Brak sygnałów breach w odpowiedzi.");
  renderList("#stealer-list", exposure.infostealer || [], "Brak sygnałów infostealera w odpowiedzi.");
  renderActions(bundle.removal?.actions || []);

  $("#result-json").textContent = JSON.stringify(bundle.provider?.raw ?? bundle, null, 2);
  const result = $("#result");
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runLookup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const email = form.elements.namedItem("email").value.trim();
  const button = $("#lookup-submit");
  const note = $("#lookup-note");

  button.disabled = true;
  button.textContent = "SZUKAM…";
  note.textContent = "EmailOSINT → linked accounts → breaches → infostealer → AI synthesis";

  const payload = { email };

  try {
    let result;
    try {
      result = await requestJson(
        "/api/v1/lookup/email",
        { method: "POST", body: JSON.stringify(payload) },
        false,
      );
    } catch (error) {
      if (error.status !== 401) throw error;

      const token = operatorToken();
      if (!token) {
        $("#operator-settings").open = true;
        const authError = new Error("Backend ma prywatny provider key. Wpisz Sherlock API key w ustawieniach operatora.");
        authError.code = "OPERATOR_KEY_REQUIRED";
        throw authError;
      }

      result = await requestJson(
        "/api/v1/lookup/email",
        { method: "POST", body: JSON.stringify(payload) },
        true,
      );
    }

    renderResult(result);
    toast(`Lookup zakończony // risk ${result.risk?.level || "unknown"}.`);
    note.textContent = "Gotowe. Po zmianach prywatności uruchom ten sam lookup ponownie i porównaj wynik.";
  } catch (error) {
    toast(`${error.code || "ERROR"}: ${error.message}`, true);
    note.textContent = "Lookup nie zakończył się poprawnie. Backend nie udaje wyniku zastępczego.";
  } finally {
    button.disabled = false;
    button.textContent = "SPRAWDŹ ŚLAD";
  }
}

async function bootstrap() {
  $("#lookup-form").addEventListener("submit", runLookup);

  const saved = sessionStorage.getItem("sherlock_api_key");
  if (saved) $("#api-key").value = saved;

  try {
    const health = await requestJson("/api/v1/health", {}, false);
    state.deploymentMode = health.deployment_mode || "UNKNOWN";
    $("#service-status").innerHTML = "<i></i> ONLINE";
    $("#service-status").classList.add("online");
    $("#deployment-mode").textContent =
      health.primary_lookup_engine?.provider === "EmailOSINT"
        ? "EMAILOSINT READY"
        : (health.deployment_mode || "PRIVACY CENTER");
  } catch {
    $("#service-status").innerHTML = "<i></i> OFFLINE";
    $("#service-status").classList.add("offline");
  }
}

document.addEventListener("DOMContentLoaded", bootstrap);
