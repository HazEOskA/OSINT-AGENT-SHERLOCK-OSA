"use strict";

(() => {
  const $ = (selector) => document.querySelector(selector);
  const MAX_FIELD_ROWS = 256;
  const MAX_SIGNAL_CARDS = 400;

  function valueText(value) {
    if (value === null) return "null";
    if (value === undefined) return "";
    if (typeof value === "boolean") return value ? "TAK" : "NIE";
    if (typeof value === "number") return String(value);
    return String(value);
  }

  function flatten(value, prefix = "", output = [], depth = 0) {
    if (output.length >= MAX_FIELD_ROWS || depth > 8) return output;

    if (
      value === null ||
      value === undefined ||
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      if (prefix) output.push([prefix, valueText(value)]);
      return output;
    }

    if (Array.isArray(value)) {
      value.slice(0, 128).forEach((item, index) => {
        flatten(item, prefix ? `${prefix}[${index}]` : `[${index}]`, output, depth + 1);
      });
      return output;
    }

    if (typeof value === "object") {
      Object.entries(value).slice(0, 256).forEach(([key, child]) => {
        const next = prefix ? `${prefix}.${key}` : key;
        flatten(child, next, output, depth + 1);
      });
    }
    return output;
  }

  function collectUrls(value, urls = new Set(), depth = 0) {
    if (depth > 8 || urls.size >= 128 || value == null) return urls;
    if (typeof value === "string") {
      const candidate = value.trim();
      if (/^https?:\/\//i.test(candidate)) urls.add(candidate);
      return urls;
    }
    if (Array.isArray(value)) {
      value.slice(0, 128).forEach((item) => collectUrls(item, urls, depth + 1));
      return urls;
    }
    if (typeof value === "object") {
      Object.values(value).slice(0, 256).forEach((item) => collectUrls(item, urls, depth + 1));
    }
    return urls;
  }

  function makeLink(url, label = "otwórz źródło") {
    const link = document.createElement("a");
    link.href = url;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    link.textContent = `↗ ${label}`;
    return link;
  }

  function renderFieldRows(container, value, options = {}) {
    container.replaceChildren();
    const rows = flatten(value);
    if (!rows.length) {
      const empty = document.createElement("p");
      empty.className = "parity-empty";
      empty.textContent = options.empty || "Brak dodatkowych pól.";
      container.append(empty);
      return;
    }

    for (const [key, rawValue] of rows) {
      const row = document.createElement("div");
      row.className = "parity-field";
      const name = document.createElement("span");
      name.textContent = key;
      const valueEl = document.createElement("strong");
      valueEl.textContent = rawValue;
      if (rawValue === "[REDACTED]") valueEl.classList.add("redacted");
      row.append(name, valueEl);
      container.append(row);
    }
  }

  function signalTitle(signal, index) {
    const source = signal && signal.source ? String(signal.source) : "unknown";
    return source === "unknown" ? `Sygnał ${index + 1}` : source;
  }

  function renderCards(container, items, type) {
    container.replaceChildren();
    if (!items || !items.length) {
      const empty = document.createElement("div");
      empty.className = "parity-empty-card";
      empty.textContent = "Brak wyników w tej kategorii.";
      container.append(empty);
      return;
    }

    items.slice(0, MAX_SIGNAL_CARDS).forEach((item, index) => {
      const card = document.createElement("article");
      card.className = `parity-card parity-${type}`;

      const head = document.createElement("div");
      head.className = "parity-card-head";
      const titleWrap = document.createElement("div");
      const eyebrow = document.createElement("span");
      eyebrow.textContent = type.toUpperCase();
      const title = document.createElement("h4");
      title.textContent = type === "signal"
        ? signalTitle(item, index)
        : String(
            item && (
              item.title || item.name || item.site || item.service || item.domain || item.origin_url
            ) || `${type} ${index + 1}`
          );
      titleWrap.append(eyebrow, title);

      if (type === "signal") {
        const status = document.createElement("b");
        const state = String(item.status || "OBSERVED");
        status.className = `parity-status parity-status-${state.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
        status.textContent = state === "FOUND"
          ? "ZNALEZIONE"
          : state === "NOT_FOUND"
            ? "BRAK"
            : "SYGNAŁ";
        head.append(titleWrap, status);
      } else {
        head.append(titleWrap);
      }
      card.append(head);

      const bodyValue = type === "signal"
        ? (item.provider_payload || item.fields || item)
        : item;

      const fields = document.createElement("div");
      fields.className = "parity-fields";
      renderFieldRows(fields, bodyValue);
      card.append(fields);

      const urls = [
        ...new Set([
          ...((item && Array.isArray(item.urls)) ? item.urls : []),
          ...collectUrls(bodyValue),
        ]),
      ].filter((url) => typeof url === "string" && /^https?:\/\//i.test(url));

      if (urls.length) {
        const links = document.createElement("div");
        links.className = "parity-links";
        urls.slice(0, 30).forEach((url) => links.append(makeLink(url)));
        card.append(links);
      }

      container.append(card);
    });
  }

  function renderEventCounts(counts) {
    const container = $("#email-event-counts");
    if (!container) return;
    container.replaceChildren();
    const entries = Object.entries(counts || {});
    if (!entries.length) {
      container.textContent = "Brak eventów providera.";
      return;
    }
    entries.forEach(([name, count]) => {
      const chip = document.createElement("span");
      chip.textContent = `${name}: ${count}`;
      container.append(chip);
    });
  }

  function renderAi(emailosint) {
    const ai = emailosint.identity && emailosint.identity.ai_profile || {};
    const headline = ai.headline || ai.summary || emailosint.identity && emailosint.identity.summary;
    $("#email-ai-headline").textContent = headline || "Brak syntezy AI od EmailOSINT.";
    $("#email-ai-summary").textContent = ai.summary || headline || "";
    $("#email-ai-reason").textContent = ai.reason || emailosint.risk && emailosint.risk.reason || "Brak dodatkowego uzasadnienia providera.";

    const risk = ai.risk || emailosint.risk && emailosint.risk.level;
    $("#email-ai-risk").textContent = risk ? String(risk).toUpperCase() : "UNKNOWN";

    const payload = $("#email-ai-payload");
    renderFieldRows(payload, ai.payload || {}, { empty: "Provider nie zwrócił dodatkowych pól AI." });
  }

  function renderMeta(emailosint) {
    const timeline = emailosint.timeline || {};
    $("#email-first-seen").textContent = timeline.first_seen || "—";
    $("#email-last-seen").textContent = timeline.last_seen || "—";
    const meta = $("#email-meta-fields");
    renderFieldRows(meta, timeline.meta || {}, { empty: "Brak dodatkowych metadanych." });
  }

  function renderParity(emailosint) {
    const section = $("#email-parity-section");
    if (!section) return;

    if (!emailosint) {
      section.hidden = true;
      return;
    }

    section.hidden = false;
    const parity = emailosint.parity || {};
    const identity = emailosint.identity || {};
    const exposure = emailosint.exposure || {};
    const provenance = emailosint.provenance || {};

    $("#email-provider-source-count").textContent = String(
      parity.provider_source_count || (provenance.sources || []).length || 0
    );
    $("#email-provider-event-count").textContent = String(
      parity.events_total || provenance.events_total || 0
    );
    $("#email-provider-signal-count").textContent = String(
      parity.identity_signal_count || (identity.signals || []).length || 0
    );
    $("#email-parity-state").textContent =
      parity.safe_provider_payload_preserved ? "PARITY+ SAFE PAYLOAD" : "NORMALIZED";

    renderAi(emailosint);
    renderMeta(emailosint);
    renderEventCounts(provenance.event_counts || parity.event_counts || {});

    const sourceList = $("#email-provider-source-list");
    sourceList.replaceChildren();
    const sources = provenance.sources || [];
    if (sources.length) {
      sources.forEach((source) => {
        const chip = document.createElement("span");
        chip.textContent = source;
        sourceList.append(chip);
      });
    } else {
      sourceList.textContent = "Brak nazw źródeł w odpowiedzi providera.";
    }

    renderCards($("#email-signals-list"), identity.signals || [], "signal");
    renderCards($("#email-breach-parity-list"), exposure.breaches || [], "breach");
    renderCards($("#email-stealer-parity-list"), exposure.infostealer || [], "infostealer");

    const breachSummary = $("#email-breach-summary-fields");
    renderFieldRows(
      breachSummary,
      exposure.breach_summary || {},
      { empty: "Brak zbiorczych metadanych breach." }
    );
    const stealerSummary = $("#email-stealer-summary-fields");
    renderFieldRows(
      stealerSummary,
      exposure.infostealer_summary || {},
      { empty: "Brak zbiorczych metadanych infostealera." }
    );
  }

  function tryRenderFromRaw() {
    const raw = $("#result-json");
    if (!raw) return;
    const text = raw.textContent.trim();
    if (!text) return;
    try {
      const bundle = JSON.parse(text);
      renderParity(bundle.emailosint || null);
    } catch {
      // Existing UI owns user-visible error handling; parity rendering stays fail-closed.
    }
  }

  function bootstrap() {
    const raw = $("#result-json");
    if (!raw) return;
    const observer = new MutationObserver(tryRenderFromRaw);
    observer.observe(raw, { childList: true, characterData: true, subtree: true });
    tryRenderFromRaw();
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
