const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../dashboard/app.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../dashboard/index.html"), "utf8");
const lines = source.split("\n");

function fixture(rows) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:"", textContent:"", listeners:{}, addEventListener(event, handler) { this.listeners[event] = handler; }});
    return elements.get(id);
  };
  const button = dataset => ({dataset, disabled:false, addEventListener(event, handler) { this[event] = handler; }});
  const activityButtons = attribute => linesFromHtml(attribute).map(line => {
    const dataset = {};
    for (const [, key, value] of line.matchAll(/data-([a-z-]+)="([^"]+)"/g)) dataset[key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    return button(dataset);
  });
  const selectors = {
    "[data-findings-page]": ["first", "previous", "next", "last"].map(action => button({findingsPage:action})),
    "[data-new-view]": activityButtons("data-new-view"),
    "[data-fixed-view]": activityButtons("data-fixed-view"),
  };
  const state = {
    findings:rows, origin:"Both", severity:"All", exposureStatus:"DetectedAndPending",
    assetClass:"All", subscription:"All", hideNonReporting:false, reportingDays:30,
    includeDiscoveredOnly:false, recommendationTypes:new Set(["Vulnerability"]),
    domains:new Set(["Devices", "Cloud"]), team:"All", search:"", newPeriod:"day",
    newPeriodStart:"", newPeriodEnd:"", newPeriodFilter:false, remediationPeriodFilter:false,
    latestRunChangesOnly:false, snapshotTimeMs:Date.parse("2026-10-24T00:00:00Z"),
  };
  const context = vm.createContext({
    state, findingsList:{mode:"findings", page:0, scopeKey:""},
    $:element, document:{querySelectorAll:selector => selectors[selector] || []},
    fmt:value => String(value), watchlistEvidence:() => "",
    pivotToCve:row => { context.selectedCve = row.CveId; }, showDetail:() => {},
    clearSelectedWorkItem:() => {}, activateView:view => { state.activeView = view; context.render(); },
    table:(id, columns, displayed, handler) => { context.displayed = displayed; context.rowHandler = handler; },
    originMatches:() => true, assetClassMatches:() => true, subscriptionMatches:() => true,
    reportingMatches:() => true, findingKind:() => "Vulnerability", findingDomain:() => "Devices",
    latestRunChangeMatches:() => true, datasetSnapshotMs:() => state.snapshotTimeMs,
    detected:row => ["Open", "Reopened", "DetectionReturned"].includes(row.FindingStatus),
    pending:row => ["PendingConfirmation", "PendingVerification"].includes(row.FindingStatus),
    truthy:value => value === true,
  });
  vm.runInContext(lines.find(line => line.startsWith("const FINDINGS_PAGE_SIZE=")), context);
  for (const name of ["normalizedCve", "matchesSearch", "newPeriodRange", "firstObservedMatches", "fixedInPeriodMatches", "filteredFindings", "findingKnownExploit", "aggregateBy", "rowCounts", "cveRowsFor"]) {
    vm.runInContext(lines.find(line => line.startsWith(`function ${name}(`)), context);
  }
  vm.runInContext('function exposureStatusMatches(row){return state.exposureStatus==="All"||row.FindingStatus!=="Fixed";}', context);
  const body = source.split("function renderFindingsList(rows){")[1].split("\n}")[0];
  vm.runInContext(`function renderFindingsList(rows){${body}\n}`, context);
  context.render = () => context.renderFindingsList(context.filteredFindings());
  for (const token of ['document.querySelectorAll("[data-new-view]")', 'document.querySelectorAll("[data-fixed-view]")', '$("findingsMode").addEventListener', '$("findingsSearch").addEventListener', 'document.querySelectorAll("[data-findings-page]")']) {
    vm.runInContext(lines.find(line => line.includes(token)), context);
  }
  return {context, state, element, selectors, render:context.render};
}

function linesFromHtml(attribute) {
  return html.split("\n").filter(line => line.includes(`<button `) && line.includes(`${attribute}=`));
}

function finding(index, overrides = {}) {
  return {
    CveId:`CVE-2026-${1000 + index}`, DeviceId:`device-${index}`, DeviceName:`machine-${index}`,
    FindingStatus:"Open", Severity:index < 2 ? "Critical" : index < 5 ? "High" : index < 20005 ? "Medium" : "Low",
    PriorityScore:100000 - index, FirstObservedUtc:"2026-10-23T12:00:00Z", ...overrides,
  };
}

test("all severities are reachable in 100-row pages, including the last partial page", () => {
  const app = fixture(Array.from({length:32128}, (_, index) => finding(index)));
  app.render();
  assert.equal(app.context.displayed.length, 100);
  assert.equal(app.context.displayed[99].Severity, "Medium");
  assert.match(app.element("findingsPageStatus").textContent, /1-100 of 32128 finding instances/);
  const [first, previous, next, last] = app.selectors["[data-findings-page]"];
  assert.equal(previous.disabled, true);
  next.click();
  assert.equal(app.context.displayed[0].DeviceId, "device-100");
  assert.match(app.element("findingsPageStatus").textContent, /101-200/);
  last.click();
  assert.equal(app.context.displayed.length, 28);
  assert.equal(app.context.displayed[0].Severity, "Low");
  assert.equal(next.disabled, true);
  previous.click();
  assert.equal(app.context.displayed.length, 100);
  first.click();
  assert.equal(app.context.displayed[0].DeviceId, "device-0");
});

test("search finds records outside the displayed page and resets pagination", () => {
  const app = fixture(Array.from({length:250}, (_, index) => finding(index)));
  app.render();
  app.selectors["[data-findings-page]"][2].click();
  app.element("findingsSearch").listeners.input({target:{value:"machine-249"}});
  assert.equal(app.context.displayed.length, 1);
  assert.equal(app.context.displayed[0].DeviceId, "device-249");
  assert.equal(app.context.findingsList.page, 0);
  assert.equal(app.element("searchFilter").value, "machine-249");
  app.element("findingsSearch").listeners.input({target:{value:"no-match"}});
  assert.equal(app.context.displayed.length, 0);
  assert.match(app.element("findingsPageStatus").textContent, /No matching finding instances/);
  assert.ok(app.selectors["[data-findings-page]"].every(button => button.disabled));
});

test("first-seen metric buttons preserve filters and open matching findings or distinct CVEs", () => {
  const rows = Array.from({length:205}, (_, index) => finding(index, {CveId:`CVE-2026-${1000 + index % 105}`}));
  rows.push(finding(999, {FirstObservedUtc:"2026-10-20T00:00:00Z"}));
  const app = fixture(rows);
  const [findingsButton, cvesButton] = app.selectors["[data-new-view]"];
  app.render();
  app.selectors["[data-findings-page]"][2].click();
  findingsButton.click();
  assert.equal(app.context.findingsList.page, 0);
  assert.match(app.element("findingsPageStatus").textContent, /of 205 finding instances/);
  cvesButton.click();
  assert.equal(app.state.activeView, "overview");
  assert.equal(app.state.newPeriodFilter, true);
  assert.equal(app.context.displayed.length, 100);
  assert.match(app.element("findingsPageStatus").textContent, /of 105 distinct CVEs/);
  assert.equal(new Set(app.context.displayed.map(row => row.CveId)).size, 100);
  const firstPageIds = new Set(app.context.displayed.map(row => row.CveId));
  app.selectors["[data-findings-page]"][2].click();
  assert.equal(app.context.displayed.length, 5);
  assert.ok(app.context.displayed.every(row => !firstPageIds.has(row.CveId)));
  app.context.rowHandler(app.context.displayed[0]);
  assert.equal(app.context.selectedCve, app.context.displayed[0].CveId);
  app.state.severity = "Critical";
  app.render();
  assert.equal(app.context.findingsList.page, 0);
  assert.equal(app.context.displayed.length, 2);
});

test("remediation drill-down includes fixed and pending observations and groups matching CVEs", () => {
  const app = fixture([
    finding(1, {FindingStatus:"Fixed", EffectiveRemediationUtc:"2026-10-23T18:00:00Z"}),
    finding(2, {CveId:"CVE-2026-1001", FindingStatus:"PendingConfirmation", EffectiveRemediationUtc:"2026-10-23T18:00:00Z"}),
    finding(3, {FindingStatus:"Fixed", EffectiveRemediationUtc:"2026-10-20T18:00:00Z"}),
  ]);
  const [findingsButton, cvesButton] = app.selectors["[data-fixed-view]"];
  findingsButton.click();
  assert.equal(app.state.exposureStatus, "All");
  assert.equal(app.state.remediationPeriodFilter, true);
  assert.equal(app.context.displayed.length, 2);
  cvesButton.click();
  assert.equal(app.context.displayed.length, 1);
  assert.equal(app.context.displayed[0].FindingInstances, 2);
  assert.equal(app.context.displayed[0].PendingFindings, 1);
  assert.equal(app.context.displayed[0].FixedFindings, 1);
});
