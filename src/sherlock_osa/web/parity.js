"use strict";

(() => {
  const $ = (selector) => document.querySelector(selector);
  const MAX_FIELD_ROWS = 256;
  const MAX_SIGNAL_CARDS = 500;
  const SOCIAL_CATEGORY_ORDER = [
    "GOOGLE",
    "DATING",
    "SOCIAL",
    "MESSAGING",
    "DEVELOPER",
    "GAMING",
    "MUSIC",
    "VIDEO",
    "SHOPPING",
    "FINANCE",
    "FORUMS",
    "OTHER",
  ];
  const SENSITIVE_BUCKET_ORDER = [
    "CREATOR_PLATFORMS",
    "ADULT_COMMUNITIES",
    "DATING_SEXUAL_OVERLAP",
    "LINK_IN_BIO_MONETIZATION",
    "HISTORICAL_ARCHIVE",
    "OTHER_ADULT",
  ];
  const SENSITIVE_BUCKET_LABELS = {
    CREATOR_PLATFORMS: "Creator platforms",
    ADULT_COMMUNITIES: "Adult communities / forums",
    DATING_SEXUAL_OVERLAP: "Dating / sexual-social overlap",
    LINK_IN_BIO_MONETIZATION: "Link-in-bio / monetization",
    HISTORICAL_ARCHIVE: "Historical / archive evidence",
    OTHER_ADULT: "Other sensitive public signals",
  };

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
        flatten(child, prefix ? `${prefix}.${key}` : key, output, depth + 1);
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
        status.textContent = state === "FOUND" ? "ZNALEZIONE" : state === "NOT_FOUND" ? "BRAK" : "SYGNAŁ";
        head.append(titleWrap, status);
      } else {
        head.append(titleWrap);
      }
      card.append(head);

      const bodyValue = type === "signal" ? (item.provider_payload || item.fields || item) : item;
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
    renderFieldRows(
      $("#email-ai-payload"),
      ai.payload || {},
      { empty: "Provider nie zwrócił dodatkowych pól AI." }
    );
  }

  function renderMeta(emailosint) {
    const timeline = emailosint.timeline || {};
    $("#email-first-seen").textContent = timeline.first_seen || "—";
    $("#email-last-seen").textContent = timeline.last_seen || "—";
    renderFieldRows(
      $("#email-meta-fields"),
      timeline.meta || {},
      { empty: "Brak dodatkowych metadanych." }
    );
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
    renderFieldRows(
      $("#email-breach-summary-fields"),
      exposure.breach_summary || {},
      { empty: "Brak zbiorczych metadanych breach." }
    );
    renderFieldRows(
      $("#email-stealer-summary-fields"),
      exposure.infostealer_summary || {},
      { empty: "Brak zbiorczych metadanych infostealera." }
    );
  }

  function ensureSocialSection() {
    let section = $("#social-graph-section");
    if (section) return section;

    section = document.createElement("section");
    section.className = "report-section parity-social-section";
    section.id = "social-graph-section";
    section.hidden = true;

    const header = document.createElement("div");
    header.className = "report-section-head";
    const headerCopy = document.createElement("div");
    const eyebrow = document.createElement("span");
    eyebrow.textContent = "SOCIAL GRAPH ULTRA V3";
    const title = document.createElement("h3");
    title.textContent = "Google, sociale, komunikatory i dating";
    headerCopy.append(eyebrow, title);
    const state = document.createElement("small");
    state.id = "social-graph-state";
    state.textContent = "EVIDENCE-FIRST";
    header.append(headerCopy, state);
    section.append(header);

    const truth = document.createElement("article");
    truth.className = "parity-ai-card";
    const truthTitle = document.createElement("span");
    truthTitle.textContent = "CO TO ZNACZY";
    const truthText = document.createElement("p");
    truthText.className = "parity-ai-summary";
    truthText.textContent = "FOUND oznacza pozytywny sygnał ze źródła. Ta sama nazwa użytkownika na dwóch serwisach nie jest automatycznie dowodem, że to ta sama osoba.";
    truth.append(truthTitle, truthText);
    section.append(truth);

    const stats = document.createElement("div");
    stats.className = "email-parity-grid";
    [
      ["social-total", "SYGNAŁY", "0"],
      ["social-found", "ZNALEZIONE", "0"],
      ["social-google", "GOOGLE", "0"],
      ["social-dating", "DATING", "0"],
      ["social-social", "SOCIAL", "0"],
      ["social-messaging", "MESSAGING", "0"],
    ].forEach(([id, label, value]) => {
      const card = document.createElement("article");
      const labelEl = document.createElement("span");
      labelEl.textContent = label;
      const valueEl = document.createElement("strong");
      valueEl.id = id;
      valueEl.textContent = value;
      card.append(labelEl, valueEl);
      stats.append(card);
    });
    section.append(stats);

    const categories = document.createElement("div");
    categories.id = "social-category-list";
    categories.className = "parity-social-categories";
    section.append(categories);

    const graphBlock = document.createElement("div");
    graphBlock.className = "parity-section-block";
    const graphHeader = document.createElement("header");
    const graphCopy = document.createElement("div");
    const graphEyebrow = document.createElement("span");
    graphEyebrow.className = "parity-subtitle";
    graphEyebrow.textContent = "SERVICE RELATIONSHIP GRAPH";
    const graphTitle = document.createElement("h4");
    graphTitle.textContent = "Trop → serwis → username";
    graphCopy.append(graphEyebrow, graphTitle);
    graphHeader.append(graphCopy);
    graphBlock.append(graphHeader);
    const graphMeta = document.createElement("div");
    graphMeta.id = "social-relationship-meta";
    graphMeta.className = "parity-event-counts";
    graphBlock.append(graphMeta);
    section.append(graphBlock);

    const paritySection = $("#email-parity-section");
    const anchor = paritySection && paritySection.nextElementSibling;
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(section, anchor);
    else if ($("#result")) $("#result").append(section);
    return section;
  }

  function socialStatusText(status) {
    const state = String(status || "OBSERVED").toUpperCase();
    if (state === "FOUND") return "ZNALEZIONE";
    if (state === "NOT_FOUND") return "BRAK";
    if (state === "RATE_LIMITED") return "RATE LIMIT";
    if (state === "BLOCKED") return "ZABLOKOWANE";
    if (state === "UNRELIABLE") return "NIEWIARYGODNE";
    if (state === "TIMEOUT") return "TIMEOUT";
    if (state === "ERROR") return "BŁĄD";
    return state;
  }

  function renderSocialAccountCard(account, sensitive = false) {
    const card = document.createElement("article");
    card.className = sensitive
      ? "parity-card parity-signal sensitive-signal-card"
      : "parity-card parity-signal";

    const head = document.createElement("div");
    head.className = "parity-card-head";
    const titleWrap = document.createElement("div");
    const source = document.createElement("span");
    source.textContent = account.source || "SOURCE";
    const title = document.createElement("h4");
    title.textContent = account.service || "unknown service";
    titleWrap.append(source, title);

    const status = document.createElement("b");
    const state = String(account.status || "OBSERVED");
    status.className = `parity-status parity-status-${state.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    status.textContent = socialStatusText(state);
    head.append(titleWrap, status);
    card.append(head);

    const fields = document.createElement("div");
    fields.className = "parity-fields";
    const compact = {
      username: account.username || undefined,
      kategoria: account.category || undefined,
      warstwa: account.sensitive_bucket || undefined,
      poziom_dowodu: account.evidence_tier || undefined,
      pewnosc_dowodowa: typeof account.confidence === "number"
        ? `${Math.round(account.confidence * 100)}%`
        : undefined,
      origin: account.origin || undefined,
    };
    renderFieldRows(fields, compact, { empty: "Publiczny sygnał konta." });
    card.append(fields);

    const urls = [
      account.profile_url,
      ...((Array.isArray(account.evidence_urls)) ? account.evidence_urls : []),
    ].filter((url, index, arr) => typeof url === "string" && /^https?:\/\//i.test(url) && arr.indexOf(url) === index);
    if (urls.length) {
      const links = document.createElement("div");
      links.className = "parity-links";
      urls.slice(0, 12).forEach((url) => links.append(makeLink(url, "profil / dowód")));
      card.append(links);
    }
    return card;
  }

  function ensureSensitiveSection() {
    let section = $("#sensitive-intelligence-section");
    if (section) return section;

    section = document.createElement("section");
    section.className = "report-section sensitive-intelligence-section";
    section.id = "sensitive-intelligence-section";
    section.hidden = true;

    const shell = document.createElement("details");
    shell.className = "sensitive-intelligence-shell";
    shell.id = "sensitive-intelligence-shell";

    const shellSummary = document.createElement("summary");
    shellSummary.className = "sensitive-intelligence-summary";
    const titleWrap = document.createElement("div");
    const eyebrow = document.createElement("span");
    eyebrow.textContent = "⚠ SENSITIVE INTELLIGENCE";
    const title = document.createElement("strong");
    title.id = "sensitive-intelligence-title";
    title.textContent = "NSFW / ADULT — CLICK TO REVEAL";
    titleWrap.append(eyebrow, title);
    const count = document.createElement("b");
    count.id = "sensitive-intelligence-count";
    count.textContent = "0 SIGNALS";
    shellSummary.append(titleWrap, count);
    shell.append(shellSummary);

    const body = document.createElement("div");
    body.className = "sensitive-intelligence-body";

    const truth = document.createElement("article");
    truth.className = "sensitive-truth-card";
    const truthTitle = document.createElement("strong");
    truthTitle.textContent = "EVIDENCE BOUNDARY";
    const truthText = document.createElement("p");
    truthText.textContent = "To są publiczne sygnały źródłowe. Sama zgodność username nie dowodzi, że profile należą do tej samej osoby. Treści graficzne nie są automatycznie pobierane ani wyświetlane.";
    truth.append(truthTitle, truthText);
    body.append(truth);

    const stats = document.createElement("div");
    stats.className = "sensitive-stats";
    [
      ["sensitive-found", "FOUND"],
      ["sensitive-direct", "DIRECT PUBLIC"],
      ["sensitive-observed", "OBSERVED"],
      ["sensitive-limited", "BLOCKED / LIMITED"],
    ].forEach(([id, label]) => {
      const card = document.createElement("article");
      const labelEl = document.createElement("span");
      labelEl.textContent = label;
      const valueEl = document.createElement("strong");
      valueEl.id = id;
      valueEl.textContent = "0";
      card.append(labelEl, valueEl);
      stats.append(card);
    });
    body.append(stats);

    const buckets = document.createElement("div");
    buckets.id = "sensitive-bucket-list";
    buckets.className = "sensitive-bucket-list";
    body.append(buckets);
    shell.append(body);
    section.append(shell);

    const result = $("#result");
    const raw = result && result.querySelector(".raw-result");
    if (result && raw) result.insertBefore(section, raw);
    else if (result) result.append(section);
    return section;
  }

  function fallbackSensitive(graph) {
    const adult = graph && graph.categories && Array.isArray(graph.categories.ADULT)
      ? graph.categories.ADULT.filter((item) => item.status !== "NOT_FOUND")
      : [];
    return {
      default_collapsed: true,
      media_autoload: false,
      accounts: adult,
      sections: { OTHER_ADULT: adult },
      summary: {
        signals_total: adult.length,
        found_total: adult.filter((item) => item.status === "FOUND").length,
        direct_public_profiles: adult.filter((item) => item.status === "FOUND" && item.profile_url).length,
        observed_total: adult.filter((item) => item.status === "OBSERVED").length,
        blocked_total: adult.filter((item) => item.status === "BLOCKED").length,
        rate_limited_total: adult.filter((item) => item.status === "RATE_LIMITED").length,
        unreliable_total: adult.filter((item) => item.status === "UNRELIABLE").length,
      },
    };
  }

  function renderSensitiveIntelligence(graph) {
    const section = ensureSensitiveSection();
    const sensitive = graph && graph.sensitive_intelligence
      ? graph.sensitive_intelligence
      : fallbackSensitive(graph || {});
    const accounts = Array.isArray(sensitive.accounts) ? sensitive.accounts : [];
    if (!accounts.length) {
      section.hidden = true;
      $("#sensitive-intelligence-shell").open = false;
      return;
    }

    section.hidden = false;
    const summary = sensitive.summary || {};
    $("#sensitive-intelligence-count").textContent = `${summary.signals_total || accounts.length} SIGNALS`;
    $("#sensitive-found").textContent = String(summary.found_total || 0);
    $("#sensitive-direct").textContent = String(summary.direct_public_profiles || 0);
    $("#sensitive-observed").textContent = String(summary.observed_total || 0);
    $("#sensitive-limited").textContent = String(
      (summary.blocked_total || 0) +
      (summary.rate_limited_total || 0) +
      (summary.unreliable_total || 0)
    );

    const container = $("#sensitive-bucket-list");
    container.replaceChildren();
    const sections = sensitive.sections || {};

    SENSITIVE_BUCKET_ORDER.forEach((bucket) => {
      const items = Array.isArray(sections[bucket]) ? sections[bucket] : [];
      if (!items.length) return;

      const details = document.createElement("details");
      details.className = "sensitive-bucket";
      const bucketSummary = document.createElement("summary");
      const label = document.createElement("span");
      label.textContent = SENSITIVE_BUCKET_LABELS[bucket] || bucket;
      const count = document.createElement("b");
      count.textContent = `${items.length} signals`;
      bucketSummary.append(label, count);
      details.append(bucketSummary);

      const cards = document.createElement("div");
      cards.className = "parity-card-list sensitive-card-list";
      [...items]
        .sort((a, b) => {
          const aFound = a.status === "FOUND" ? 0 : 1;
          const bFound = b.status === "FOUND" ? 0 : 1;
          if (aFound !== bFound) return aFound - bFound;
          return Number(b.confidence || 0) - Number(a.confidence || 0);
        })
        .slice(0, 160)
        .forEach((account) => cards.append(renderSocialAccountCard(account, true)));
      details.append(cards);
      container.append(details);
    });
  }

  function renderSocialGraph(graph) {
    const section = ensureSocialSection();
    if (!graph || !Array.isArray(graph.accounts)) {
      section.hidden = true;
      renderSensitiveIntelligence(null);
      return;
    }
    section.hidden = false;

    const summary = graph.summary || {};
    $("#social-total").textContent = String(summary.signals_total || 0);
    $("#social-found").textContent = String(summary.found_total || 0);
    $("#social-google").textContent = String(summary.google_found || 0);
    $("#social-dating").textContent = String(summary.dating_found || 0);
    $("#social-social").textContent = String(summary.social_found || 0);
    $("#social-messaging").textContent = String(summary.messaging_found || 0);

    const categories = graph.categories || {};
    const container = $("#social-category-list");
    container.replaceChildren();

    SOCIAL_CATEGORY_ORDER.forEach((category) => {
      const items = Array.isArray(categories[category]) ? categories[category] : [];
      const visible = items.filter((item) => item.status !== "NOT_FOUND");
      if (!visible.length) return;

      const block = document.createElement("section");
      block.className = "parity-section-block";
      const header = document.createElement("header");
      const copy = document.createElement("div");
      const subtitle = document.createElement("span");
      subtitle.className = "parity-subtitle";
      subtitle.textContent = category;
      const title = document.createElement("h4");
      const foundCount = visible.filter((item) => item.status === "FOUND").length;
      title.textContent = `${foundCount} znalezionych / ${visible.length} widocznych sygnałów`;
      copy.append(subtitle, title);
      header.append(copy);
      block.append(header);

      const cards = document.createElement("div");
      cards.className = "parity-card-list";
      visible
        .sort((a, b) => {
          const aFound = a.status === "FOUND" ? 0 : 1;
          const bFound = b.status === "FOUND" ? 0 : 1;
          if (aFound !== bFound) return aFound - bFound;
          return Number(b.confidence || 0) - Number(a.confidence || 0);
        })
        .slice(0, 160)
        .forEach((account) => cards.append(renderSocialAccountCard(account)));
      block.append(cards);
      container.append(block);
    });

    const relationship = graph.graph || {};
    const meta = $("#social-relationship-meta");
    meta.replaceChildren();
    [
      `nodes: ${relationship.node_count || 0}`,
      `edges: ${relationship.edge_count || 0}`,
      `wersja: ${graph.version || "v3"}`,
    ].forEach((text) => {
      const chip = document.createElement("span");
      chip.textContent = text;
      meta.append(chip);
    });

    renderSensitiveIntelligence(graph);
  }

  function tryRenderFromRaw() {
    const raw = $("#result-json");
    if (!raw) return;
    const text = raw.textContent.trim();
    if (!text) return;
    try {
      const bundle = JSON.parse(text);
      renderParity(bundle.emailosint || null);
      renderSocialGraph(bundle.social_graph || null);
    } catch {
      // Existing UI owns user-visible error handling; enrichment rendering stays fail-closed.
    }
  }

  function bootstrap() {
    const raw = $("#result-json");
    if (!raw) return;
    ensureSocialSection();
    ensureSensitiveSection();
    const observer = new MutationObserver(tryRenderFromRaw);
    observer.observe(raw, { childList: true, characterData: true, subtree: true });
    tryRenderFromRaw();
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
