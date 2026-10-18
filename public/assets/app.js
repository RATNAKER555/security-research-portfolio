"use strict";

const STATUS_LABELS = Object.freeze({
  "cve-assigned": "CVE assigned",
  "publicly-disclosed": "Disclosed finding",
  "engineering-bug": "Public patch",
  "independent-validation": "Independent validation",
  "under-coordination": "Maintainer coordination",
  queued: "Candidate review"
});

const STATUS_BAR_LABELS = Object.freeze({
  "cve-assigned": "CVE records",
  "publicly-disclosed": "Disclosed",
  "engineering-bug": "Public patches",
  "independent-validation": "Validations"
});

const TRACKER_STAGE_LABELS = Object.freeze({
  "patch-review": "Patch review",
  "public-commit": "Public commit",
  "fix-queued": "Maintainer tree",
  integration: "Integration branch",
  "fixed-upstream": "Fixed upstream",
  closed: "Closed"
});

const FOLLOW_UP_LABELS = Object.freeze({
  none: "No review scheduled",
  scheduled: "Scheduled",
  "due-soon": "Due soon",
  due: "Due today",
  overdue: "Overdue"
});

const dateFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit"
});

const dateTimeFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  timeZoneName: "short"
});

const state = {
  entries: [],
  filter: "all",
  query: "",
  operations: [],
  operationsFilter: "active"
};

function text(value) {
  return String(value ?? "");
}

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = text(content);
  return node;
}

function formatDate(value) {
  return dateFormat.format(new Date(value + "T12:00:00Z"));
}

function formatDateTime(value) {
  return dateTimeFormat.format(new Date(value));
}

function appendTerm(list, term, description) {
  const group = document.createElement("div");
  const definition = el("dd", "");
  if (description instanceof Node) definition.append(description);
  else definition.textContent = text(description);
  group.append(el("dt", "", term), definition);
  list.append(group);
}

function makeCweLink(reference) {
  const anchor = el("a", "cwe-link", reference.id + " · " + reference.name);
  anchor.href = "https://cwe.mitre.org/data/definitions/" +
    reference.id.slice(4) + ".html";
  anchor.target = "_blank";
  anchor.rel = "noreferrer noopener";
  return anchor;
}

function appendWeaknessTerms(list, weakness) {
  if (weakness.status === "pending") {
    appendTerm(list, "Primary CWE", "Pending classification");
    appendTerm(list, "Consequence CWE", "Not assigned while primary classification is pending");
    appendTerm(list, "Mapping basis", weakness.reason);
    return;
  }

  appendTerm(list, "Primary CWE", makeCweLink(weakness.primary));
  if (weakness.consequences.length === 0) {
    appendTerm(list, "Consequence CWE", "No separate consequence CWE assigned");
  } else {
    const references = el("span", "cwe-references");
    weakness.consequences.forEach((reference, index) => {
      if (index) references.append(document.createTextNode("; "));
      references.append(makeCweLink(reference));
    });
    appendTerm(list, "Consequence CWE", references);
  }
  appendTerm(list, "Mapping basis", weakness.basis);
}

function makePublicEntry(entry, index) {
  const article = el("article", "entry");
  article.dataset.status = entry.status;

  const number = el("span", "entry-number", String(index + 1).padStart(2, "0"));
  number.setAttribute("aria-hidden", "true");

  const content = el("div", "entry-content");
  const top = el("div", "entry-top");
  const meta = el("div", "entry-meta");
  meta.append(
    el("span", "entry-project", entry.project),
    el("span", "", entry.recordId)
  );
  const time = el("time", "", formatDate(entry.date));
  time.dateTime = entry.date;
  meta.append(time);
  const status = el("span", "status-pill", STATUS_LABELS[entry.status]);
  top.append(meta, status);

  const titleRow = el("div", "entry-title-row");
  titleRow.append(el("h3", "", entry.title));
  const summary = el("p", "entry-summary", entry.summary);

  const evidence = el("dl", "entry-evidence");
  appendTerm(evidence, "Observed primitive", entry.evidence.primitive);
  appendTerm(evidence, "Validation", entry.evidence.validation);
  appendTerm(evidence, "Scope", entry.evidence.boundary);
  appendWeaknessTerms(evidence, entry.weakness);

  const credit = el("p", "entry-credit");
  credit.append(
    el("strong", "", "Attribution: "),
    document.createTextNode(text(entry.credit))
  );

  const footer = el("div", "entry-footer");
  const tags = el("div", "tags");
  for (const value of entry.tags) tags.append(el("span", "tag", value));

  const links = el("div", "entry-links");
  for (const source of entry.links) {
    const anchor = el("a", "source-link", source.label + " ↗");
    anchor.href = source.url;
    anchor.target = "_blank";
    anchor.rel = "noreferrer noopener";
    links.append(anchor);
  }
  footer.append(tags, links);

  content.append(top, titleRow, summary, evidence, credit, footer);
  article.append(number, content);
  return article;
}

function makePrivateEntry(entry) {
  const card = el("article", "private-card");
  const top = el("div", "private-card-top");
  top.append(
    el("span", "", STATUS_LABELS[entry.status]),
    el("span", "", "updated " + formatDate(entry.date))
  );
  const count = el("div", "private-card-count", String(entry.count).padStart(2, "0"));
  count.setAttribute("aria-label", entry.count + " records");
  const heading = el("h3", "", entry.title);
  const summary = el("p", "", entry.summary);
  const tags = el("div", "private-tags");
  for (const value of entry.tags) tags.append(el("span", "", value));
  card.append(top, count, heading, summary, tags);
  return card;
}

function searchableText(entry) {
  return [
    entry.project,
    entry.recordId,
    entry.title,
    entry.summary,
    entry.credit,
    entry.evidence?.primitive,
    entry.evidence?.validation,
    entry.evidence?.boundary,
    entry.weakness?.primary?.id,
    entry.weakness?.primary?.name,
    entry.weakness?.basis,
    entry.weakness?.reason,
    ...(entry.weakness?.consequences ?? []).flatMap((item) => [item.id, item.name]),
    ...(entry.tags ?? [])
  ].join(" ").toLocaleLowerCase("en");
}

function selectedEntries() {
  return state.entries.filter((entry) => {
    const hasStatus = state.filter === "all" || entry.status === state.filter;
    const hasQuery = !state.query || searchableText(entry).includes(state.query);
    return hasStatus && hasQuery;
  });
}

function observeReveals(scope = document) {
  const nodes = scope.querySelectorAll(".reveal:not(.visible)");
  if (
    window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
    !("IntersectionObserver" in window)
  ) {
    nodes.forEach((node) => node.classList.add("visible"));
    return;
  }
  const observer = new IntersectionObserver((records) => {
    for (const record of records) {
      if (!record.isIntersecting) continue;
      record.target.classList.add("visible");
      observer.unobserve(record.target);
    }
  }, { threshold: 0.08 });
  nodes.forEach((node) => observer.observe(node));
}

function renderEntries() {
  const container = document.querySelector("#entries");
  const empty = document.querySelector("#empty-state");
  const selected = selectedEntries();
  container.replaceChildren(...selected.map(makePublicEntry));
  empty.hidden = selected.length !== 0;
  observeReveals(container);
}

function renderPrivateEntries(entries) {
  const container = document.querySelector("#private-entries");
  container.replaceChildren(...entries.map(makePrivateEntry));
  observeReveals(container);
}

function renderStatusBars(entries) {
  const container = document.querySelector("#status-bars");
  const maximum = Math.max(
    1,
    ...Object.keys(STATUS_BAR_LABELS).map(
      (status) => entries.filter((entry) => entry.status === status).length
    )
  );

  const bars = Object.entries(STATUS_BAR_LABELS).map(([status, label]) => {
    const count = entries.filter((entry) => entry.status === status).length;
    const className = status === "independent-validation"
      ? "validation"
      : status === "cve-assigned"
        ? "cve"
        : "";
    const block = el("div", ("status-bar " + className).trim());
    const heading = document.createElement("div");
    heading.append(el("span", "", label), el("span", "", count));
    const track = el("div", "status-track");
    const fill = document.createElement("i");
    fill.style.width = ((count / maximum) * 100) + "%";
    track.append(fill);
    block.append(heading, track);
    return block;
  });
  container.replaceChildren(...bars);
}

function setProfile(profile) {
  document.querySelector("#footer-name").textContent = profile.name;
  for (const id of ["header-github", "footer-github"]) {
    document.querySelector("#" + id).href = profile.github;
  }
  for (const id of ["header-gitlab", "footer-gitlab"]) {
    document.querySelector("#" + id).href = profile.gitlab;
  }
}

function setMetrics(summary) {
  const values = {
    "metric-cves": summary.assignedCves,
    "metric-public": summary.publicOriginalContributions,
    "metric-coordinating": summary.underCoordination,
    "metric-validated": summary.validatedDistinctFindings,
    "metric-validations": summary.independentValidations
  };
  for (const [id, value] of Object.entries(values)) {
    document.querySelector("#" + id).textContent = value;
  }
}

function setTaxonomy(taxonomy) {
  document.querySelector("#taxonomy-release").textContent =
    taxonomy.name + " " + taxonomy.version;
  const published = document.querySelector("#taxonomy-published");
  published.dateTime = taxonomy.published;
  published.textContent = formatDate(taxonomy.published);
}

function externalLink(label, url, className = "") {
  const anchor = el("a", className, label);
  anchor.href = url;
  anchor.target = "_blank";
  anchor.rel = "noreferrer noopener";
  return anchor;
}

function makeTrackerRecord(record) {
  const article = el("article", "tracker-row");
  article.dataset.stage = record.stage;

  const identity = el("div", "tracker-identity");
  const meta = el("div", "tracker-meta");
  meta.append(
    el("span", "tracker-id", record.id),
    el("span", "", record.project)
  );
  identity.append(
    meta,
    el("h3", "", record.title),
    externalLink("Primary source ↗", record.sourceUrl, "tracker-source")
  );

  const lifecycle = el("div", "tracker-lifecycle");
  lifecycle.append(el("span", "tracker-cell-label", "Lifecycle"));
  const stage = el("strong", "tracker-stage", TRACKER_STAGE_LABELS[record.stage] || record.stage);
  const locations = record.locations.length
    ? record.locations.join(" · ")
    : "Public commit; branch promotion not observed in the scanned window";
  lifecycle.append(stage, el("p", "", locations));
  const activity = el("time", "", "activity " + formatDate(record.lastPublicActivityOn));
  activity.dateTime = record.lastPublicActivityOn;
  lifecycle.append(activity);

  const attribution = el("div", "tracker-attribution");
  attribution.append(el("span", "tracker-cell-label", "Attribution"));
  const confirmed = record.creditState === "confirmed";
  attribution.append(
    el("strong", confirmed ? "credit-confirmed" : "credit-pending", confirmed ? "✓ Confirmed" : "Review needed"),
    el("p", "credit-evidence", record.creditEvidence)
  );
  if (record.relatedSources.length) {
    const related = el("div", "related-sources");
    for (const source of record.relatedSources) {
      related.append(externalLink("Related fix " + source.commit.slice(0, 7) + " ↗", source.url));
    }
    attribution.append(related);
  }

  const action = el("div", "tracker-action");
  action.append(el("span", "tracker-cell-label", "Next review"));
  const due = el("strong", "follow-up-state " + record.followUpState, FOLLOW_UP_LABELS[record.followUpState]);
  action.append(due);
  if (record.followUpOn) {
    const time = el("time", "", formatDate(record.followUpOn));
    time.dateTime = record.followUpOn;
    action.append(time);
  }
  action.append(el("p", "", record.nextAction));
  if (record.cves.length) {
    action.append(el("small", "tracker-cve-list", record.cves.join(" · ")));
  }

  const sourceState = el("span", "tracker-check-state " + record.checkState);
  sourceState.textContent = record.checkState === "verified" ? "source verified" : "last verified snapshot";
  sourceState.title = record.checkDetail;
  identity.append(sourceState);

  article.append(identity, lifecycle, attribution, action);
  return article;
}

function renderDiscoveries(discoveries) {
  const panel = document.querySelector("#credit-discoveries");
  const list = document.querySelector("#credit-discovery-list");
  if (!discoveries.length) {
    panel.hidden = true;
    list.replaceChildren();
    return;
  }
  const rows = discoveries.map((item) => {
    const row = el("article", "credit-discovery");
    const copy = el("div", "");
    copy.append(
      el("strong", "", item.subject),
      el("p", "", item.creditEvidence + " · " + item.source + " / " + item.location)
    );
    row.append(copy, externalLink(item.commit.slice(0, 7) + " ↗", item.url));
    return row;
  });
  list.replaceChildren(...rows);
  panel.hidden = false;
}

function renderTracker(data) {
  const records = [...data.records].sort((left, right) => {
    const leftDate = left.followUpOn || "9999-12-31";
    const rightDate = right.followUpOn || "9999-12-31";
    return leftDate.localeCompare(rightDate) || left.id.localeCompare(right.id);
  });
  document.querySelector("#tracker-records").replaceChildren(...records.map(makeTrackerRecord));
  document.querySelector("#tracker-active").textContent = data.summary.active;
  document.querySelector("#tracker-credit").textContent = data.summary.creditConfirmed;
  document.querySelector("#tracker-followup").textContent = data.summary.followUpDue;
  document.querySelector("#tracker-cves").textContent = data.summary.cves;

  const checked = document.querySelector("#monitor-checked");
  checked.dateTime = data.generatedAt;
  checked.textContent = formatDateTime(data.generatedAt);
  const mode = document.querySelector("#monitor-mode");
  const dot = document.querySelector("#monitor-state-dot");
  if (data.summary.checkErrors) {
    mode.textContent = "Partial source check";
    dot.className = "partial";
  } else if (data.mode === "live") {
    mode.textContent = "Live source check";
    dot.className = "live";
  } else {
    mode.textContent = "Verified source snapshot";
    dot.className = "snapshot";
  }
  renderDiscoveries(data.discoveries);
  observeReveals(document.querySelector("#tracking"));
}

async function loadTracker() {
  const error = document.querySelector("#tracker-error");
  try {
    const response = await fetch("data/tracker.json", { cache: "no-store" });
    if (!response.ok) throw new Error("tracker data returned " + response.status);
    renderTracker(await response.json());
  } catch (failure) {
    error.textContent = "The public attribution monitor could not be loaded: " + failure.message;
    error.hidden = false;
  }
}

function operationsFollowUpState(record) {
  if (!record.followUpOn) return "none";
  const today = new Date();
  const localToday = [
    today.getFullYear(),
    String(today.getMonth() + 1).padStart(2, "0"),
    String(today.getDate()).padStart(2, "0")
  ].join("-");
  if (record.followUpOn < localToday) return "overdue";
  if (record.followUpOn === localToday) return "due";
  return "scheduled";
}

function makeOperationsRecord(record) {
  const article = el("article", "operations-row");
  article.dataset.state = record.state;
  const identity = el("div", "operations-identity");
  const meta = el("div", "operations-meta");
  meta.append(el("span", "", record.id), el("span", "", record.project));
  identity.append(meta, el("h3", "", record.title));
  if (record.publicUrl) {
    identity.append(externalLink("Public record ↗", record.publicUrl, "operations-source"));
  } else {
    identity.append(el("span", "operations-visibility", record.visibility));
  }

  const status = el("div", "operations-status");
  status.append(el("strong", "", record.state.replaceAll("-", " ")));
  const dates = el("dl", "");
  if (record.reportedOn) appendTerm(dates, "Reported", formatDate(record.reportedOn));
  appendTerm(dates, "Last activity", formatDate(record.lastActivityOn));
  status.append(dates);

  const action = el("div", "operations-action");
  const followState = operationsFollowUpState(record);
  action.append(el("strong", "operations-follow " + followState, FOLLOW_UP_LABELS[followState]));
  if (record.followUpOn) {
    const time = el("time", "", formatDate(record.followUpOn));
    time.dateTime = record.followUpOn;
    action.append(time);
  }
  action.append(el("p", "", record.nextAction), el("small", "", record.source));
  article.append(identity, status, action);
  return article;
}

function selectedOperations() {
  const activeStates = new Set(["reported", "patch-review", "fix-queued", "ready-to-report"]);
  return state.operations.filter((record) => {
    if (state.operationsFilter === "all") return true;
    if (state.operationsFilter === "active") return activeStates.has(record.state);
    if (state.operationsFilter === "reported") return record.state === "reported";
    if (state.operationsFilter === "follow-up") return Boolean(record.followUpOn);
    return true;
  }).sort((left, right) => {
    const leftDate = left.followUpOn || "9999-12-31";
    const rightDate = right.followUpOn || "9999-12-31";
    return leftDate.localeCompare(rightDate) || left.id.localeCompare(right.id);
  });
}

function renderOperations() {
  document.querySelector("#operations-records").replaceChildren(
    ...selectedOperations().map(makeOperationsRecord)
  );
}

function setupOperationsControls() {
  for (const button of document.querySelectorAll(".operations-filter")) {
    button.addEventListener("click", () => {
      state.operationsFilter = button.dataset.operationsFilter;
      for (const candidate of document.querySelectorAll(".operations-filter")) {
        const active = candidate === button;
        candidate.classList.toggle("active", active);
        candidate.setAttribute("aria-pressed", String(active));
      }
      renderOperations();
    });
  }
}

async function loadPrivateTracker() {
  const path = document.body.dataset.privateTracker;
  if (!path) return;
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error("private tracker returned " + response.status);
  const data = await response.json();
  state.operations = data.records;
  const followUpsDue = data.records.filter((record) =>
    ["due", "overdue"].includes(operationsFollowUpState(record))
  ).length;
  document.querySelector("#operations-reported").textContent = data.counts.underCoordination;
  document.querySelector("#operations-due").textContent = followUpsDue;
  document.querySelector("#operations-ready").textContent = data.records.filter(
    (record) => record.state === "ready-to-report"
  ).length;
  document.querySelector("#operations-public").textContent = data.records.filter(
    (record) => record.visibility === "public"
  ).length;
  const updated = document.querySelector("#operations-updated");
  updated.dateTime = data.updated;
  updated.textContent = formatDate(data.updated);
  document.querySelector("#private-operations").hidden = false;
  setupOperationsControls();
  renderOperations();
}

function setupControls() {
  for (const button of document.querySelectorAll(".filter")) {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      for (const candidate of document.querySelectorAll(".filter")) {
        const active = candidate === button;
        candidate.classList.toggle("active", active);
        candidate.setAttribute("aria-pressed", String(active));
      }
      renderEntries();
    });
  }

  document.querySelector("#entry-search").addEventListener("input", (event) => {
    state.query = event.currentTarget.value.trim().toLocaleLowerCase("en");
    renderEntries();
  });
}

async function start() {
  const response = await fetch("data/findings.json", { cache: "no-store" });
  if (!response.ok) throw new Error("research data returned " + response.status);
  const data = await response.json();

  state.entries = data.publicEntries;
  setProfile(data.profile);
  setMetrics(data.summary);
  setTaxonomy(data.taxonomy);
  renderStatusBars(data.publicEntries);
  renderPrivateEntries(data.privateEntries);

  const reviewed = document.querySelector("#last-updated");
  reviewed.dateTime = data.updated;
  reviewed.textContent = formatDate(data.updated);
  document.querySelector("#year").textContent = new Date().getFullYear();

  setupControls();
  renderEntries();
  await loadTracker();
  await loadPrivateTracker();
  observeReveals();
}

start().catch((error) => {
  const container = document.querySelector("#entries");
  container.replaceChildren(
    el("p", "load-error", "The public research record could not be loaded: " + error.message)
  );
});
