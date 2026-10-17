"use strict";

const STATUS_LABELS = Object.freeze({
  "cve-assigned": "CVE assigned",
  "publicly-disclosed": "Disclosed finding",
  "engineering-bug": "Public patch",
  "independent-validation": "Independent validation",
  "under-coordination": "Under coordination",
  queued: "Research queue"
});

const STATUS_BAR_LABELS = Object.freeze({
  "cve-assigned": "CVE records",
  "publicly-disclosed": "Disclosed",
  "engineering-bug": "Public patches",
  "independent-validation": "Validations"
});

const dateFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit"
});

const state = {
  entries: [],
  filter: "all",
  query: ""
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

function appendTerm(list, term, description) {
  const group = document.createElement("div");
  group.append(el("dt", "", term), el("dd", "", description));
  list.append(group);
}

function makePublicEntry(entry, index) {
  const article = el("article", "entry reveal");
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
  appendTerm(evidence, "Claim boundary", entry.evidence.boundary);

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
  const card = el("article", "private-card reveal");
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
  renderStatusBars(data.publicEntries);
  renderPrivateEntries(data.privateEntries);

  const reviewed = document.querySelector("#last-updated");
  reviewed.dateTime = data.updated;
  reviewed.textContent = formatDate(data.updated);
  document.querySelector("#year").textContent = new Date().getFullYear();

  setupControls();
  renderEntries();
  observeReveals();
}

start().catch((error) => {
  const container = document.querySelector("#entries");
  container.replaceChildren(
    el("p", "load-error", "The public research record could not be loaded: " + error.message)
  );
});
