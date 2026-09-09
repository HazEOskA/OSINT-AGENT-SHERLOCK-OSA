"use strict";

const $ = (selector) => document.querySelector(selector);
const OPERATOR_KEY_STORAGE = "sherlock_api_key";

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.setTimeout(() => { element.hidden = true; }, 5000);
}

function operatorToken() {
  return ($("#api-key") && $("#api-key").value.trim()) ||
    localStorage.getItem(OPERATOR_KEY_STORAGE) || "";
}

function setOperatorAuthState(authorized) {
  const settings = $("#operator-settings");
  const summary = settings && settings.querySelector("summary");
  const input = $("#api-key");
  const label = settings && settings.querySelector('label[for="api-key"]');
  if (!settings || !summary || !input || !label) return;
  summary.textContent = authorized ? "OPERATOR AUTH ✓" : "Ustawienia operatora";
  input.hidden = authorized;
  label.hidden = authorized;
  if (authorized) settings.open = false;
}

function rememberOperatorToken(token) {
  const value = String(token || "").trim();
  if (!value) return;
  localStorage.setItem(OPERATOR_KEY_STORAGE, value);
  $("#api-key").value = value;
  setOperatorAuthState(true);
}

async function requestJson(path, options = {}) {
  const token = operatorToken();
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = "Bearer " + token;

  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: { code: "INVALID_RESPONSE", message: "Backend zwrócił niepoprawną odpowiedź." },
  }));

  if (!response.ok) {
    const error = new Error((body.error && body.error.message) || ("HTTP " + response.status));
    error.code = (body.error && body.error.code) || "HTTP_ERROR";
    error.status = response.status;
    throw error;
  }
  return body;
}

function collectUrls(value, output = new Set(), depth = 0) {
  if (depth > 6 || value == null) return output;
  if (typeof value === "string") {
    if (/^https?:\/\//i.test(value.trim())) output.add(value.trim());
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 128)) collectUrls(item, output, depth + 1);
    return output;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value).slice(0, 128)) {
      collectUrls(item, output, depth + 1);
    }
  }
  return output;
}

function compactPlain(value, depth = 0) {
  if (depth > 3 || value == null) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => compactPlain(item, depth + 1))
      .filter(Boolean).slice(0, 8).join(" · ");
  }
  if (typeof value === "object") {
    const preferred = [
      "platform", "service", "site", "name", "title", "username", "handle",
      "domain", "status", "date", "first_seen", "last_seen", "message", "reason", "description"
    ];
    const parts = [];
    for (const key of preferred) {
      if (value[key] !== undefined && value[key] !== null) {
        const rendered = compactPlain(value[key], depth + 1);
        if (rendered) parts.push(rendered);
      }
    }
    if (!parts.length) {
      for (const [key, item] of Object.entries(value).slice(0, 8)) {
        if (/password|credential|secret|token|cookie|session/i.test(key)) continue;
        const rendered = compactPlain(item, depth + 1);
        if (rendered && !/^https?:\/\//i.test(rendered)) {
          parts.push(key + ": " + rendered);
        }
      }
    }
    return [...new Set(parts)].slice(0, 8).join(" · ");
  }
  return String(value);
}

function makeEvidenceLinks(urls, source) {
  const wrap = document.createElement("div");
  wrap.className = "evidence-links";
  for (const url of urls) {
    const link = document.createElement("a");
    link.href = url;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    link.textContent = "↗ " + (source || "otwórz dowód");
    wrap.append(link);
  }
  return wrap;
}

function renderDataList(selector, items, emptyText) {
  const container = $(selector);
  container.replaceChildren();

  if (!items || !items.length) {
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
    text.textContent = compactPlain(item) || "Znaleziono publiczny sygnał.";
    article.append(text);

    const urls = [...collectUrls(item)].slice(0, 12);
    if (urls.length) article.append(makeEvidenceLinks(urls, "otwórz dowód"));
    container.append(article);
  }
}

function statusLabel(status) {
  return {
    CONFIRMED: "POTWIERDZONE",
    PROBABLE: "BARDZO PRAWDOPODOBNE",
    POSSIBLE: "MOŻLIWE",
    UNVERIFIED: "NIEPOTWIERDZONE",
    CONFLICTED: "SPRZECZNE DANE",
  }[status] || status || "NIEZNANE";
}

function renderFindings(findings) {
  const container = $("#findings-list");
  container.replaceChildren();

  if (!findings || !findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent = "Brak ustaleń z obecnego zestawu źródeł.";
    container.append(empty);
    return;
  }

  for (const finding of findings) {
    const article = document.createElement("article");
    article.className = "finding-card";

    const head = document.createElement("div");
    head.className = "finding-head";

    const titleWrap = document.createElement("div");
    const kind = document.createElement("span");
    kind.className = "finding-kind";
    kind.textContent = finding.kind || "FINDING";

    const title = document.createElement("h4");
    title.textContent = finding.title || finding.value || "Ustalenie";
    titleWrap.append(kind, title);

    const status = document.createElement("b");
    status.className = "finding-status status-" + String(finding.status || "").toLowerCase();
    status.textContent = statusLabel(finding.status);
    head.append(titleWrap, status);

    const value = document.createElement("p");
    value.className = "finding-value";
    value.textContent = finding.value || "";

    const meta = document.createElement("p");
    meta.className = "finding-meta";
    meta.textContent = "Źródła: " + String(finding.source_count || 0);

    article.append(head, value, meta);

    const hardLinks = (finding.sources || []).filter((source) => source.url);
    if (hardLinks.length) {
      const links = document.createElement("div");
      links.className = "evidence-links";
      for (const source of hardLinks.slice(0, 20)) {
        const link = document.createElement("a");
        link.href = source.url;
        link.target = "_blank";
        link.rel = "noreferrer noopener";
        link.textContent = "↗ " + (source.source || "dowód");
        links.append(link);
      }
      article.append(links);
    } else {
      const noLink = document.createElement("small");
      noLink.className = "no-hard-link";
      noLink.textContent = "Brak bezpośredniego URL — traktuj to jako sygnał, nie twardy link.";
      article.append(noLink);
    }

    container.append(article);
  }
}

function renderEmailOsint(emailosint, error) {
  const section = $("#emailosint-section");
  if (!emailosint && !error) {
    section.hidden = true;
    return;
  }
  section.hidden = false;

  if (error) {
    $("#emailosint-status").textContent = "BŁĄD PROVIDERA";
    renderDataList("#accounts-list", [], "EmailOSINT nie zwrócił danych.");
    renderDataList("#breaches-list", [], error.message || "Błąd EmailOSINT.");
    renderDataList("#stealer-list", [], "Brak danych.");
    return;
  }

  const exposure = emailosint.exposure || {};
  const counts = exposure.counts || {};
  $("#emailosint-status").textContent = "OK";
  $("#accounts-count").textContent = String(counts.linked_accounts || 0);
  $("#breaches-count").textContent = String(counts.breaches || 0);
  $("#stealer-count").textContent = String(counts.infostealer || 0);

  renderDataList("#accounts-list", exposure.linked_accounts || [], "Nie znaleziono powiązanych kont.");
  renderDataList("#breaches-list", exposure.breaches || [], "Nie znaleziono sygnałów wycieku.");
  renderDataList("#stealer-list", exposure.infostealer || [], "Nie znaleziono sygnałów infostealera.");

  const risk = String((emailosint.risk && emailosint.risk.level) || "report").toUpperCase();
  $("#risk-badge").textContent = risk;
  $("#risk-badge").dataset.level = risk.toLowerCase();
}

function renderWarnings(bundle) {
  const warnings = [];

  if (bundle.emailosint_error) {
    warnings.push("EmailOSINT: " + (bundle.emailosint_error.message || bundle.emailosint_error.code));
  }

  for (const source of ((bundle.detective && bundle.detective.source_runs) || [])) {
    if (source.status === "ERROR") {
      warnings.push(source.source + ": źródło nie odpowiedziało (" + (source.error || "ERROR") + ")");
    }
  }

  for (const conflict of ((bundle.detective && bundle.detective.conflicts) || [])) {
    warnings.push("Sprzeczne dane: " + conflict.reason);
  }

  const section = $("#warnings-section");
  if (!warnings.length) {
    section.hidden = true;
    return;
  }

  section.hidden = false;
  renderDataList("#warnings-list", warnings, "");
}

function renderResult(bundle) {
  const detective = bundle.detective || {};
  const summary = detective.summary || {};
  const emailosint = bundle.emailosint || null;
  const findings = detective.findings || [];

  $("#result-title").textContent = (bundle.query && bundle.query.value) || "Wynik śledztwa";
  $("#source-count").textContent = String(summary.sources_checked || 0);
  $("#finding-count").textContent = String(summary.findings || findings.length || 0);

  const linkCount = findings.reduce((total, finding) => {
    return total + (finding.sources || []).filter((source) => source.url).length;
  }, 0);
  $("#link-count").textContent = String(linkCount);

  const aiSummary = emailosint && emailosint.identity && emailosint.identity.summary;
  if (aiSummary) {
    $("#case-summary").textContent = aiSummary;
  } else {
    const kind = (bundle.query && bundle.query.kind) || "trop";
    const derived = (bundle.query && bundle.query.derived_queries && bundle.query.derived_queries.length) || 0;
    $("#case-summary").textContent =
      "Przeszukano " + String(summary.sources_checked || 0) + " źródeł dla typu " + kind +
      ". Zebrano " + String(summary.findings || findings.length || 0) + " ustaleń" +
      (derived ? " po " + String(derived) + " wariantach nazwy." : ".");
  }

  renderEmailOsint(emailosint, bundle.emailosint_error);
  renderFindings(findings);
  renderWarnings(bundle);

  $("#detective-status").textContent =
    detective.status === "COMPLETED" ? "GOTOWE" : (detective.status || "ZAKOŃCZONE");

  $("#result-json").textContent = JSON.stringify(bundle, null, 2);

  const result = $("#result");
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runSearch(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const token = operatorToken();

  if (!token) {
    $("#operator-settings").open = true;
    toast("Wpisz Sherlock API key. Po pierwszym udanym wyszukiwaniu zostanie zapamiętany.", true);
    return;
  }

  const button = $("#search-submit");
  const note = $("#search-note");
  const payload = {
    kind: form.elements.namedItem("kind").value,
    query: form.elements.namedItem("query").value.trim(),
  };

  button.disabled = true;
  button.textContent = "SHERLOCK SZUKA…";
  note.textContent = "Sprawdzam źródła i idę po kolejnych publicznych tropach. To może potrwać kilka minut.";

  try {
    const result = await requestJson("/api/v1/search", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    rememberOperatorToken(token);
    renderResult(result);
    note.textContent = "Gotowe. Każdy dostępny twardy dowód ma klikalny link.";
    toast("Sherlock zakończył Full Search.");
  } catch (error) {
    if (error.status === 401) {
      localStorage.removeItem(OPERATOR_KEY_STORAGE);
      setOperatorAuthState(false);
      $("#operator-settings").open = true;
    }
    toast((error.code || "ERROR") + ": " + error.message, true);
    note.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "SZUKAJ WSZĘDZIE";
  }
}

async function bootstrap() {
  $("#search-form").addEventListener("submit", runSearch);

  const saved = localStorage.getItem(OPERATOR_KEY_STORAGE);
  if (saved) {
    $("#api-key").value = saved;
    setOperatorAuthState(true);
  } else {
    setOperatorAuthState(false);
  }

  try {
    const health = await requestJson("/api/v1/health", {});
    $("#service-status").innerHTML = "<i></i> ONLINE";
    $("#service-status").classList.add("online");
    $("#deployment-mode").textContent = health.search ? "FULL SEARCH READY" : "DETECTIVE MODE";
  } catch {
    $("#service-status").innerHTML = "<i></i> OFFLINE";
    $("#service-status").classList.add("offline");
  }
}

document.addEventListener("DOMContentLoaded", bootstrap);
