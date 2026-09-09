"use strict";

const $ = (selector) => document.querySelector(selector);
const OPERATOR_KEY_STORAGE = "sherlock_api_key";
const MAX_FEED_ROWS = 220;

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  window.setTimeout(() => {
    element.hidden = true;
  }, 5000);
}

function operatorToken() {
  const input = $("#api-key");
  return (input && input.value.trim()) ||
    localStorage.getItem(OPERATOR_KEY_STORAGE) ||
    "";
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
  const input = $("#api-key");
  if (input) input.value = value;
  setOperatorAuthState(true);
}

async function requestJson(path, options = {}) {
  const token = operatorToken();
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = "Bearer " + token;

  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({
    error: {
      code: "INVALID_RESPONSE",
      message: "Backend zwrócił niepoprawną odpowiedź.",
    },
  }));

  if (!response.ok) {
    const error = new Error(
      (body.error && body.error.message) || ("HTTP " + response.status)
    );
    error.code = (body.error && body.error.code) || "HTTP_ERROR";
    error.status = response.status;
    throw error;
  }
  return body;
}

function parseSseFrame(frame) {
  const lines = frame.split("\n");
  let eventName = "message";
  const dataLines = [];

  for (const line of lines) {
    if (line.startsWith("event:")) {
      eventName = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trimStart());
    }
  }

  if (!dataLines.length) return null;

  const raw = dataLines.join("\n");
  try {
    return { event: eventName, data: JSON.parse(raw) };
  } catch {
    return { event: eventName, data: { raw } };
  }
}

async function requestSse(path, payload, onEvent) {
  const token = operatorToken();
  const headers = {
    Accept: "text/event-stream",
    "Content-Type": "application/json",
  };
  if (token) headers.Authorization = "Bearer " + token;

  const response = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({
      error: { code: "HTTP_ERROR", message: "HTTP " + response.status },
    }));
    const error = new Error(
      (body.error && body.error.message) || ("HTTP " + response.status)
    );
    error.code = (body.error && body.error.code) || "HTTP_ERROR";
    error.status = response.status;
    throw error;
  }

  if (!response.body) {
    throw new Error("Przeglądarka nie udostępniła strumienia odpowiedzi.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let finalResult = null;

  while (true) {
    const chunk = await reader.read();
    buffer += decoder.decode(chunk.value || new Uint8Array(), {
      stream: !chunk.done,
    });
    buffer = buffer.replace(/\r\n/g, "\n");

    let separator = buffer.indexOf("\n\n");
    while (separator !== -1) {
      const frame = buffer.slice(0, separator);
      buffer = buffer.slice(separator + 2);
      const parsed = parseSseFrame(frame);

      if (parsed) {
        onEvent(parsed.event, parsed.data);

        if (parsed.event === "case_result") {
          finalResult = parsed.data;
        }

        if (parsed.event === "error") {
          const body = parsed.data || {};
          const error = new Error(
            (body.error && body.error.message) || "Błąd strumienia Sherlock."
          );
          error.code = (body.error && body.error.code) || "STREAM_ERROR";
          throw error;
        }
      }
      separator = buffer.indexOf("\n\n");
    }

    if (chunk.done) break;
  }

  if (!finalResult) {
    throw new Error("Sherlock zakończył strumień bez raportu końcowego.");
  }
  return finalResult;
}

function collectUrls(value, output = new Set(), depth = 0) {
  if (depth > 6 || value == null) return output;

  if (typeof value === "string") {
    const candidate = value.trim();
    if (/^https?:\/\//i.test(candidate)) output.add(candidate);
    return output;
  }

  if (Array.isArray(value)) {
    for (const item of value.slice(0, 128)) {
      collectUrls(item, output, depth + 1);
    }
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

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => compactPlain(item, depth + 1))
      .filter(Boolean)
      .slice(0, 8)
      .join(" · ");
  }

  if (typeof value === "object") {
    const preferred = [
      "platform",
      "service",
      "site",
      "name",
      "title",
      "username",
      "handle",
      "domain",
      "status",
      "date",
      "breachdate",
      "breach_date",
      "first_seen",
      "last_seen",
      "message",
      "reason",
      "description",
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
        if (/password|credential|secret|token|cookie|session/i.test(key)) {
          continue;
        }
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
    if (urls.length) {
      article.append(makeEvidenceLinks(urls, "otwórz dowód"));
    }
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

function statusRank(status) {
  return {
    CONFIRMED: 0,
    PROBABLE: 1,
    POSSIBLE: 2,
    CONFLICTED: 3,
    UNVERIFIED: 4,
  }[status] ?? 9;
}

function findingExplanation(finding) {
  if (finding.status === "CONFIRMED") {
    return "Kilka niezależnych źródeł wspiera ten sam trop.";
  }
  if (finding.status === "PROBABLE") {
    return "Powiązanie jest mocne, ale Sherlock zostawia margines niepewności.";
  }
  if (finding.status === "CONFLICTED") {
    return "Źródła są ze sobą sprzeczne — Sherlock nie zgaduje.";
  }
  if (finding.status === "POSSIBLE") {
    return "To sensowny trop, ale potrzebuje jeszcze potwierdzenia.";
  }
  return "Pojedynczy sygnał — nie traktuj go jako potwierdzonej tożsamości.";
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

  const ordered = [...findings].sort((a, b) => {
    const rank = statusRank(a.status) - statusRank(b.status);
    if (rank !== 0) return rank;
    return Number(b.confidence || 0) - Number(a.confidence || 0);
  });

  for (const finding of ordered.slice(0, 160)) {
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
    status.className =
      "finding-status status-" + String(finding.status || "").toLowerCase();
    status.textContent = statusLabel(finding.status);
    head.append(titleWrap, status);

    const value = document.createElement("p");
    value.className = "finding-value";
    value.textContent = finding.value || "";

    const explanation = document.createElement("p");
    explanation.className = "finding-explanation";
    explanation.textContent = findingExplanation(finding);

    const meta = document.createElement("p");
    meta.className = "finding-meta";
    meta.textContent =
      "Niezależne źródła: " +
      String(finding.source_count || 0) +
      " · pewność dowodowa: " +
      String(Math.round(Number(finding.confidence || 0) * 100)) +
      "%";

    article.append(head, value, explanation, meta);

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
      noLink.textContent =
        "Brak bezpośredniego URL — to sygnał, nie twardy link do dowodu.";
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
    $("#accounts-count").textContent = "0";
    $("#breaches-count").textContent = "0";
    $("#stealer-count").textContent = "0";
    renderDataList("#accounts-list", [], "EmailOSINT nie zwrócił danych.");
    renderDataList(
      "#breaches-list",
      [],
      error.message || "Błąd EmailOSINT."
    );
    renderDataList("#stealer-list", [], "Brak danych.");
    return;
  }

  const exposure = emailosint.exposure || {};
  const counts = exposure.counts || {};
  $("#emailosint-status").textContent = "OK";
  $("#accounts-count").textContent = String(counts.linked_accounts || 0);
  $("#breaches-count").textContent = String(counts.breaches || 0);
  $("#stealer-count").textContent = String(counts.infostealer || 0);

  renderDataList(
    "#accounts-list",
    exposure.linked_accounts || [],
    "Nie znaleziono powiązanych kont."
  );
  renderDataList(
    "#breaches-list",
    exposure.breaches || [],
    "Nie znaleziono sygnałów wycieku."
  );
  renderDataList(
    "#stealer-list",
    exposure.infostealer || [],
    "Nie znaleziono sygnałów infostealera."
  );

  const risk = String(
    (emailosint.risk && emailosint.risk.level) || "report"
  ).toUpperCase();
  $("#risk-badge").textContent = risk;
  $("#risk-badge").dataset.level = risk.toLowerCase();
}

function renderIdentity(clusters, findings) {
  const container = $("#identity-list");
  container.replaceChildren();
  $("#identity-count").textContent =
    String((clusters || []).length) + " KLASTRÓW";

  if (!clusters || !clusters.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent =
      "Brak wystarczająco mocnych relacji do utworzenia klastra tożsamości.";
    container.append(empty);
    return;
  }

  const byId = new Map((findings || []).map((finding) => [
    finding.finding_id,
    finding,
  ]));

  for (const cluster of clusters.slice(0, 50)) {
    const article = document.createElement("article");
    article.className = "identity-card";

    const head = document.createElement("div");
    head.className = "identity-head";

    const title = document.createElement("strong");
    title.textContent =
      cluster.status +
      " · " +
      String(Math.round(Number(cluster.confidence || 0) * 100)) +
      "%";

    const families = document.createElement("span");
    families.textContent = (cluster.source_families || []).join(" + ");
    head.append(title, families);
    article.append(head);

    const members = document.createElement("div");
    members.className = "identity-members";
    for (const findingId of cluster.finding_ids || []) {
      const finding = byId.get(findingId);
      const chip = document.createElement("span");
      chip.textContent = finding
        ? (finding.kind + ": " + finding.value)
        : findingId;
      members.append(chip);
    }
    article.append(members);

    const reason = document.createElement("p");
    reason.textContent =
      "Dlaczego połączone: " +
      ((cluster.reasons || []).join(" · ") || "wspólny twardy dowód");
    article.append(reason);

    container.append(article);
  }
}

function renderTimeline(events) {
  const container = $("#timeline-list");
  container.replaceChildren();
  $("#timeline-count").textContent =
    String((events || []).length) + " ZDARZEŃ";

  if (!events || !events.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent = "Brak dat, z których można zbudować oś czasu.";
    container.append(empty);
    return;
  }

  const ordered = [...events].sort((a, b) =>
    String(a.timestamp).localeCompare(String(b.timestamp))
  );

  for (const event of ordered.slice(0, 200)) {
    const article = document.createElement("article");
    article.className = "timeline-item";

    const time = document.createElement("time");
    time.dateTime = event.timestamp || "";
    const date = new Date(event.timestamp);
    time.textContent = Number.isNaN(date.getTime())
      ? String(event.timestamp || "")
      : date.toLocaleString("pl-PL", {
          year: "numeric",
          month: "short",
          day: "2-digit",
        });

    const body = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = event.title || event.event_type || "Zdarzenie";
    const detail = document.createElement("p");
    detail.textContent =
      (event.identifier_kind || "") +
      ": " +
      (event.identifier_value || "");
    body.append(title, detail);

    article.append(time, body);

    if (event.url) {
      const link = document.createElement("a");
      link.href = event.url;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      link.textContent = "↗";
      article.append(link);
    }

    container.append(article);
  }
}

function sourceStatusLabel(run) {
  if (run.status === "COMPLETED" && run.rate_limited) return "PARTIAL / RATE LIMIT";
  return {
    COMPLETED: "PASS",
    SKIPPED: "POMINIĘTE",
    ERROR: "BŁĄD",
    TIMEOUT: "TIMEOUT",
    UNKNOWN: "UNKNOWN",
  }[run.status] || run.status || "UNKNOWN";
}

function sourceReason(run) {
  if (run.reason === "MISSING_CREDENTIAL") return "brak opcjonalnego klucza API";
  if (run.reason && run.reason.startsWith("MODE_")) return "pominięte przez wybrany tryb";
  if (run.reason === "QUICK_SKIPS_HISTORICAL") return "QUICK pomija źródła historyczne";
  if (run.error) return "błąd źródła: " + run.error;
  if (run.rate_limited) return "provider ograniczył część zapytań";
  return "dowody: " + String(run.evidence_count || 0);
}

function renderSourceRuns(runs) {
  const container = $("#source-runs");
  container.replaceChildren();
  $("#source-run-count").textContent =
    String((runs || []).length) + " ŹRÓDEŁ";

  if (!runs || !runs.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent = "Brak danych o przebiegu źródeł.";
    container.append(empty);
    return;
  }

  for (const run of runs) {
    const article = document.createElement("article");
    article.className =
      "source-run source-run-" + String(run.status || "unknown").toLowerCase();

    const top = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = run.source || "unknown";
    const status = document.createElement("b");
    status.textContent = sourceStatusLabel(run);
    top.append(name, status);

    const meta = document.createElement("p");
    meta.textContent =
      (run.source_family || "source") +
      " · " +
      sourceReason(run) +
      (run.duration_ms ? " · " + String(run.duration_ms) + " ms" : "");

    article.append(top, meta);
    container.append(article);
  }
}

function renderGraph(graph) {
  const container = $("#graph-list");
  if (!container) return;
  container.replaceChildren();

  const nodes = new Map(((graph && graph.nodes) || []).map((node) => [node.node_id, node]));
  const edges = (graph && graph.edges) || [];

  if (!edges.length) {
    const empty = document.createElement("div");
    empty.className = "empty-item";
    empty.textContent = "Brak relacji grafu do pokazania.";
    container.append(empty);
    return;
  }

  for (const edge of edges.slice(0, 80)) {
    const left = nodes.get(edge.from_node_id);
    const right = nodes.get(edge.to_node_id);
    const article = document.createElement("article");
    article.className = "graph-edge";

    const relation = document.createElement("b");
    relation.textContent =
      edge.edge_type === "SUPPORTED_BY"
        ? "WSPIERANE PRZEZ"
        : edge.edge_type === "PIVOT"
          ? "NOWY TROP Z"
          : "POWIĄZANIE";

    const path = document.createElement("p");
    const leftLabel = left ? (left.label || left.kind) : edge.from_node_id;
    const rightLabel = right ? (right.label || right.source || right.kind) : edge.to_node_id;
    path.textContent = leftLabel + " → " + rightLabel;

    article.append(relation, path);

    if (right && right.url) {
      const link = document.createElement("a");
      link.href = right.url;
      link.target = "_blank";
      link.rel = "noreferrer noopener";
      link.textContent = "↗ dowód";
      article.append(link);
    }
    container.append(article);
  }
}

function renderWarnings(bundle) {
  const warnings = [];

  if (bundle.report && Array.isArray(bundle.report.warnings)) {
    warnings.push(...bundle.report.warnings);
  }

  if (bundle.emailosint_error) {
    warnings.push(
      "EmailOSINT: " +
      (bundle.emailosint_error.message || bundle.emailosint_error.code)
    );
  }

  const detective = bundle.detective || {};
  for (const conflict of detective.conflicts || []) {
    warnings.push("Sprzeczne dane: " + (conflict.reason || "konflikt źródeł"));
  }

  const unique = [...new Set(warnings)].slice(0, 60);
  const section = $("#warnings-section");

  if (!unique.length) {
    section.hidden = true;
    return;
  }

  section.hidden = false;
  renderDataList("#warnings-list", unique, "");
}

function renderResult(bundle) {
  const detective = bundle.detective || {};
  const summary = detective.summary || {};
  const report = bundle.report || {};
  const findings = detective.findings || [];

  $("#result-title").textContent =
    (bundle.query && bundle.query.value) || "Wynik śledztwa";
  $("#report-headline").textContent = report.headline || "";
  $("#case-summary").textContent =
    report.summary || "Sherlock zakończył analizę.";

  $("#source-count").textContent = String(summary.sources_checked || 0);
  $("#finding-count").textContent = String(summary.findings || findings.length || 0);
  $("#confirmed-count").textContent = String(summary.confirmed_findings || 0);
  $("#identifier-count").textContent = String(summary.identifiers_seen || 0);
  $("#duration-count").textContent =
    (Number(summary.duration_ms || 0) / 1000).toFixed(1) + "s";
  $("#link-count").textContent = String(
    report.hard_links !== undefined
      ? report.hard_links
      : findings.reduce((total, finding) => {
          return total + (finding.sources || []).filter((source) => source.url).length;
        }, 0)
  );

  renderEmailOsint(bundle.emailosint || null, bundle.emailosint_error || null);
  renderFindings(findings);
  renderIdentity(detective.identity_clusters || [], findings);
  renderTimeline(detective.timeline || []);
  renderSourceRuns(detective.source_runs || []);
  renderWarnings(bundle);

  const graph = detective.graph || {};
  renderGraph(graph);
  $("#graph-summary").textContent =
    String(graph.node_count || 0) +
    " NODES / " +
    String(graph.edge_count || 0) +
    " EDGES";

  $("#detective-status").textContent =
    detective.status === "COMPLETED"
      ? "GOTOWE"
      : (detective.status || "ZAKOŃCZONE");

  $("#result-json").textContent = JSON.stringify(bundle, null, 2);

  const result = $("#result");
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

function liveEventMessage(event, payload) {
  const module = payload && payload.module ? String(payload.module) : "";

  if (event === "search_started") {
    return "START · " + String(payload.kind || "") + " · " + String(payload.mode || "");
  }
  if (event === "investigation_started") {
    return "Detective Core uruchomiony · tryb " + String(payload.mode || "");
  }
  if (event === "source_started") {
    return "→ " + module + " · sprawdzam";
  }
  if (event === "source_completed") {
    return "✓ " + module + " · " + String(payload.duration_ms || 0) + " ms";
  }
  if (event === "source_skipped") {
    const reason =
      payload.reason === "MISSING_CREDENTIAL"
        ? "brak klucza API"
        : String(payload.reason || "pominięte");
    return "– " + module + " · " + reason;
  }
  if (event === "source_timeout") {
    return "⌛ " + module + " · timeout";
  }
  if (event === "source_error") {
    return "✕ " + module + " · błąd źródła";
  }
  if (event === "source_rate_limited") {
    return "⚠ " + module + " · rate limit";
  }
  if (event === "pivot_discovered") {
    return (
      "↳ nowy trop · " +
      String(payload.kind || "") +
      " · " +
      String(payload.value || "")
    );
  }
  if (event === "evidence_blocked") {
    return "🛡 zablokowano podejrzaną treść ze źródła";
  }
  if (event === "finding_confirmed") {
    return "★ potwierdzone · " + String(payload.value || payload.title || "");
  }
  if (event === "conflict_detected") {
    return "⚠ wykryto sprzeczne dowody";
  }
  if (event === "identity_resolution_completed") {
    return "Identity Resolver · klastry: " + String(payload.cluster_count || 0);
  }
  if (event === "timeline_ready") {
    return "Timeline · zdarzenia: " + String(payload.event_count || 0);
  }
  if (event === "case_report_ready") {
    return "RAPORT GOTOWY · " + String(payload.headline || "");
  }
  if (event === "investigation_completed") {
    return "Detective Core zakończony";
  }
  if (event === "case_result") {
    return "✓ SHERLOCK MAX ZAKOŃCZONY";
  }
  return "";
}

function appendLiveEvent(event, payload) {
  const message = liveEventMessage(event, payload || {});
  if (!message) return;

  const feed = $("#live-feed");
  const row = document.createElement("div");
  row.className = "live-row live-" + event.replace(/_/g, "-");

  const dot = document.createElement("i");
  const text = document.createElement("span");
  text.textContent = message;

  row.append(dot, text);
  feed.append(row);

  while (feed.children.length > MAX_FEED_ROWS) {
    feed.firstElementChild.remove();
  }

  feed.scrollTop = feed.scrollHeight;
  $("#live-status").textContent =
    event === "case_result" ? "GOTOWE" : "PRACUJE";
}

async function runSearch(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const token = operatorToken();
  if (!token) {
    $("#operator-settings").open = true;
    toast(
      "Wpisz Sherlock API key. Po pierwszym udanym wyszukiwaniu zostanie zapamiętany.",
      true
    );
    return;
  }

  const button = $("#search-submit");
  const note = $("#search-note");
  const liveBox = $("#live-box");
  const feed = $("#live-feed");

  const payload = {
    kind: form.elements.namedItem("kind").value,
    mode: form.elements.namedItem("mode").value,
    query: form.elements.namedItem("query").value.trim(),
  };

  feed.replaceChildren();
  liveBox.hidden = false;
  $("#live-status").textContent = "START";

  button.disabled = true;
  button.textContent = "SHERLOCK PRACUJE…";
  note.textContent =
    "Źródła pracują na żywo. Każdy timeout, rate limit i pominięcie zobaczysz poniżej.";

  try {
    const result = await requestSse(
      "/api/v1/search/stream",
      payload,
      appendLiveEvent
    );

    rememberOperatorToken(token);
    renderResult(result);
    note.textContent =
      "Gotowe. Wynik rozdziela fakty, powiązania i hipotezy; dostępne dowody są klikalne.";
    toast("Sherlock MAX zakończył śledztwo.");
  } catch (error) {
    if (error.status === 401) {
      localStorage.removeItem(OPERATOR_KEY_STORAGE);
      setOperatorAuthState(false);
      $("#operator-settings").open = true;
    }

    $("#live-status").textContent = "BŁĄD";
    toast((error.code || "ERROR") + ": " + error.message, true);
    note.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "URUCHOM SHERLOCK MAX";
  }
}

function syncModeChip() {
  const mode = $("#search-mode").value;
  $("#mode-chip").textContent = mode;
}

async function bootstrap() {
  $("#search-form").addEventListener("submit", runSearch);
  $("#search-mode").addEventListener("change", syncModeChip);
  $("#clear-feed").addEventListener("click", () => {
    $("#live-feed").replaceChildren();
  });
  syncModeChip();

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

    if (health.search && health.search.default_mode) {
      $("#deployment-mode").textContent =
        "FULL SEARCH " + String(health.search.default_mode);
    } else {
      $("#deployment-mode").textContent = "MAX ENGINE";
    }
  } catch {
    $("#service-status").innerHTML = "<i></i> OFFLINE";
    $("#service-status").classList.add("offline");
  }
}

document.addEventListener("DOMContentLoaded", bootstrap);
