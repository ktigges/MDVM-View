"""Last modified: 2026-11-10.
Purpose: Verify dashboard exports, presentation contracts, versioning, and local-only tools.
"""

import csv
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from vulnerability_view.dataprep_cli import build_synthetic
from vulnerability_view.config import Settings
from vulnerability_view.export_writer import write_outputs


def test_dashboard_query_paging_and_drilldown_interactions():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for dashboard interaction regressions")
    result = subprocess.run(
        [node, "--test", str(Path(__file__).with_name("dashboard_queries.test.cjs"))],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_csv_json_schema_consistency(tmp_path: Path):
    data = build_synthetic(
        Settings(synthetic_seed=31, synthetic_months=6),
        [{"CveId": "CVE-2025-1234", "Severity": "High", "CvssScore": 8.8}],
    )
    write_outputs(data, tmp_path)
    for basename in ("findings", "recommendations", "recommendation-machines", "remediation-activities", "daily-summary", "collection-runs", "reconciliation"):
        json_rows = json.loads((tmp_path / "dashboard/data" / f"{basename}.json").read_text())
        with (tmp_path / "output/curated" / f"{basename}.csv").open(newline="") as handle:
            csv_rows = list(csv.DictReader(handle))
        assert len(csv_rows) == len(json_rows)
        if not json_rows:
            continue
        assert set(csv_rows[0]) == set(json_rows[0])
        assert all({"DataOrigin", "ScenarioId", "SnapshotTimeUtc", "CollectionRunId"} <= set(row) for row in json_rows)
    assert not (tmp_path / "dashboard/data/vulnerabilities.json").exists()
    assert (tmp_path / "dashboard/data/cve-details/index.json").exists()


def test_empty_exports_clear_stale_files(tmp_path: Path):
    stale_json = tmp_path / "dashboard/data/secure-scores.json"
    stale_csv = tmp_path / "output/curated/secure-scores.csv"
    stale_json.parent.mkdir(parents=True)
    stale_csv.parent.mkdir(parents=True)
    stale_json.write_text('[{"stale":true}]')
    stale_csv.write_text("stale\n")

    write_outputs({"secureScores": []}, tmp_path)

    assert json.loads(stale_json.read_text()) == []
    assert stale_csv.read_text() == ""


def test_subscription_inventory_is_exported(tmp_path: Path):
    subscriptions = [{"SubscriptionId": "subscription-1", "SubscriptionName": "Production", "State": "Enabled"}]

    write_outputs({"subscriptions": subscriptions}, tmp_path)

    assert json.loads((tmp_path / "dashboard/data/subscriptions.json").read_text()) == subscriptions
    assert "Production" in (tmp_path / "output/curated/subscriptions.csv").read_text()


def test_dashboard_files_contract():
    for path in (Path("dashboard/index.html"), Path("dashboard/app.js"), Path("dashboard/config.js"), Path("dashboard/styles.css")):
        assert path.exists()

    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()
    assert 'id="availabilityItems"' in html
    assert 'class="header-statuses"' in html
    assert "Snapshot availability" not in html
    assert "FILTER WORKSPACE" in html
    assert "Pinned snapshot" in javascript
    assert 'id="developmentWarning"' in html
    assert "localDevelopmentOnly" in javascript
    assert ".development-warning" in stylesheet


def test_dashboard_loads_snapshot_summary_then_bounded_views():
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "loadDashboardDatasets" in javascript
    assert 'apiFetch("/api/dashboard/snapshot"' in javascript
    assert 'apiFetch("/api/dashboard/query"' in javascript
    assert 'apiFetch("/api/sla-policy")' not in javascript
    assert "dashboardQuery.snapshot?.snapshotId" in javascript
    assert "signal:channel.controller.signal" in javascript
    assert "New snapshot available" in javascript
    assert "Math.max(...snapshotTimes)" not in javascript
    assert 'apiFetch(`/api/data/${name}.json`)' not in javascript
    assert "Promise.all(" not in javascript
    assert ".loading-notice.degraded" in stylesheet


def test_dashboard_streams_snapshot_pinned_exports_without_browser_csv_buffering():
    javascript = Path("dashboard/app.js").read_text()
    html = Path("dashboard/index.html").read_text()
    export_body = javascript.split("async function exportDashboardCsv(")[1].split(
        "function renderFindingsList("
    )[0]

    assert 'form.action="/api/dashboard/export"' in export_body
    assert 'input.name="payload"' in export_body
    assert "JSON.stringify(request)" in export_body
    assert ".blob(" not in export_body
    assert 'id="exportFindingsCsv"' in html
    assert 'id="reloadDashboardSnapshot"' in html
    assert "New snapshot available" in html


@pytest.mark.parametrize("view", [
    "executive", "recommendations", "overview", "workstations", "slaDashboard",
    "sla", "trend", "executiveSnapshot", "help",
])
def test_dashboard_current_navigation_has_a_matching_view(view: str):
    html = Path("dashboard/index.html").read_text()

    assert f'data-view="{view}"' in html
    assert f'<section id="{view}"' in html


def test_dashboard_counts_entities_without_hidden_instance_metrics():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "supporting evidence, not additional vulnerabilities" in html
    assert 'id="slaDashboardVisuals"' in html
    assert 'id="executiveSnapshotManagement"' in html
    assert 'id="lifecycleDetailTable"' in html
    assert 'id="newCveCount"' in html
    assert 'id="newMachineCount"' in html
    assert 'id="fixedWindowCveCount"' in html
    assert 'id="fixedWindowMachineCount"' in html
    assert '<option value="findings">' not in html
    assert "technical-metric" not in html
    assert "TechnicalEvidence" not in html
    assert "newFindingCount" not in html
    assert "fixedWindowFindingCount" not in html
    assert "function renderLegacyDashboard" not in javascript
    assert "function filteredFindings" not in javascript
    assert "refreshLegacyTracking" not in javascript
    assert "entity-sla-status" in javascript
    assert "request.filters.includeFindingEvidence=false" in javascript
    assert "request.filters.managementReporting=true" in javascript


def test_handoff_includes_local_setup_and_retained_storage_contract():
    guide = Path("PROJECT-GUIDE.md").read_text()
    ignore = Path(".gitignore").read_text().splitlines()

    assert "git clone https://github.com/ktigges/MDVM-View.git" in guide
    assert "pip install -e" in guide
    assert "authoritative Terraform state" in guide
    assert "overwrite=False" in guide
    assert "current/manifest.json" in guide
    assert "A machine is vulnerable to a CVE" in guide
    assert Path("bump-version.sh").is_file()
    assert "bump-version.sh" not in ignore
    assert "build/" in ignore
    assert "*.egg-info/" in ignore


def test_dashboard_filter_workspace_uses_compact_combined_toolbar():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()
    final_filterbar_rule = [rule for rule in re.findall(r"\.filterbar\{([^}]*)\}", stylesheet) if "background:" in rule][-1]
    final_scope_rule = [rule for rule in re.findall(r"\.scope-bar\{([^}]*)\}", stylesheet) if "background:" in rule][-1]

    assert html.index('id="scopeBar"') < html.index('id="filterBar"')
    assert 'class="scope-actions"' in html
    assert '>Filters</button>' in html
    assert "background:#e8eef2!important" in final_filterbar_rule
    assert "background:#173f59!important" in final_scope_rule
    assert "box-shadow:0 14px 28px" in stylesheet
    assert 'class="filter-check-options"' in html
    assert ".scope-bar{min-height:64px!important" in stylesheet
    assert ".filterbar fieldset{display:grid!important" in stylesheet
    assert "border:0!important" in stylesheet
    assert ".filter-toggle[aria-expanded=\"true\"]" in stylesheet
    assert "function sizeFilterPanel()" in javascript
    assert "overflow-wrap:anywhere" in stylesheet


def test_dashboard_scope_does_not_repeat_active_view():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="scopeView"' not in html
    assert '$("scopeView")' not in javascript
    assert "grid-template-columns:1fr;justify-items:start" in stylesheet
    assert "justify-content:flex-start" in stylesheet
    assert "box-shadow:0 11px 25px" in stylesheet


def test_recommendation_detail_uses_fullscreen_navigation():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="pivotPrevious"' in html
    assert 'id="pivotNext"' in html
    assert 'id="pivotPosition"' in html
    assert "navigateRecommendationDetail" in javascript
    assert "detailRecommendationIds" in javascript
    assert "fullscreen-mode" in javascript
    assert ".pivot-panel.fullscreen-mode" in stylesheet
    assert "inset:clamp(18px,3vh,36px) clamp(18px,3vw,52px)" in stylesheet
    assert "box-shadow:0 30px 80px" in stylesheet
    assert "backdrop-filter:blur(1.5px)" in stylesheet
    assert "drawer-mode" not in javascript


def test_dashboard_executive_subtiles_have_visible_contrast():
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "background:#e2e6e8" in stylesheet
    assert "background:#dde2e5" in stylesheet
    assert "border:1px solid #aab6be" in stylesheet
    assert "box-shadow:0 3px 7px" in stylesheet


def test_dashboard_header_and_scope_are_readable():
    html = Path("dashboard/index.html").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "Data refreshed · Live snapshot" in html
    assert "--topbar-height:64px" in stylesheet
    assert ".topbar h1{order:1" in stylesheet
    assert ".app-shell{width:100%;max-width:none!important" in stylesheet
    assert "grid-template-columns:216px minmax(0,1fr)!important" in stylesheet
    assert ".story-nav .nav-label" in stylesheet
    assert ".scope-bar p{grid-column:1;" in stylesheet
    assert 'id="filterCount"' in html


def test_dashboard_resets_scroll_to_top_on_refresh():
    javascript = Path("dashboard/app.js").read_text()

    assert 'history.scrollRestoration="manual"' in javascript
    assert 'window.addEventListener("pageshow"' in javascript
    assert "window.scrollTo(0,0)" in javascript


def test_dashboard_uses_microsoft_vulnerability_management_branding():
    html = Path("dashboard/index.html").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "<title>Microsoft Vulnerability Management</title>" in html
    assert "<h1>Microsoft Vulnerability Management</h1>" in html
    assert 'class="ms-logo"' in html
    assert ".brand-title" in stylesheet
    assert "#f25022" in stylesheet


def test_finding_lifecycle_badges_explain_their_meaning():
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "function findingLifecycleDescription(status)" in javascript
    assert "Defender currently reports this vulnerability on the endpoint." in javascript
    assert 'class="lifecycle-status ${esc(value)} lifecycle-tooltip"' in javascript
    assert 'data-tooltip="${esc(description)}"' in javascript
    assert ".lifecycle-tooltip:hover::after,.lifecycle-tooltip:focus-visible::after" in stylesheet


def test_dashboard_shows_global_filters_as_chips_and_clears_selected_work_item():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="activeFilterChips"' in html
    assert "activeFilterItems" in javascript
    assert "clearSelectedWorkItem" in javascript
    assert "clearSelectedWorkItem();render();" in javascript
    assert ".active-filter-chips" in stylesheet


def test_dashboard_defaults_to_vulnerabilities_devices_and_cloud():
    html = Path("dashboard/index.html").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert 'value="Misconfiguration">Misconfiguration' in html
    assert 'value="SaaS Apps">SaaS Apps' in html
    assert 'value="Identities">Identities' in html
    assert 'value="Data">Data' in html
    assert 'value="Vulnerability" checked' in html
    assert 'value="Devices" checked' in html
    assert 'value="Cloud" checked' in html
    assert '"defaultRecommendationTypes": ["Vulnerability"]' in configuration
    assert '"defaultDomains": ["Devices", "Cloud"]' in configuration


def test_dashboard_customer_logo_placeholder_is_hidden_by_default():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert Path("dashboard/customer-logo.svg").is_file()
    assert 'id="customerLogo"' in html
    assert 'src="customer-logo.svg"' in html
    assert 'alt="Customer logo" hidden' in html
    assert "customerLogo.hidden=!customLogoEnabled" in javascript
    assert "$(\"defaultLogo\").hidden=customLogoEnabled" in javascript
    assert 'id="brandLogoButton"' in html
    assert 'accept="image/png,.png"' in html
    assert 'apiFetch("/api/branding/logo"' in javascript
    assert "MAX_CUSTOMER_LOGO_BYTES" in javascript
    assert "height:30px;max-width:150px" in stylesheet
    assert "enabled: false" in configuration
    assert ".customer-logo[hidden],.customer-logo-input[hidden]{display:none!important}" in stylesheet


def test_dashboard_header_shows_authenticated_user_and_branding_access():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="signedInUser"' in html
    assert 'id="signedInUserName"' in html
    assert 'id="signedInUserAccess"' in html
    assert "function configureSignedInUser(auth)" in javascript
    assert 'auth.authorization?.brandingAdministrator?"Dashboard Administrator":"Dashboard Viewer"' in javascript
    assert "configureSignedInUser(auth);configureBranding(auth)" in javascript
    assert ".signed-in-user{" in stylesheet
    assert ".signed-in-user[hidden]{display:none!important}" in stylesheet


def test_dashboard_freshness_shows_ten_recent_collection_runs():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="freshnessSummary"' in html
    assert 'tabindex="0" aria-describedby="recentRunsPopover"' in html
    assert 'id="recentRunsPopover"' in html
    assert 'id="recentRunsList"' in html
    assert "function recentCollectionRuns()" in javascript
    assert ".slice(0,10)" in javascript
    assert "function renderRecentRuns()" in javascript
    assert "renderRecentRuns();" in javascript
    assert ".freshness:hover .recent-runs-popover,.freshness:focus-within .recent-runs-popover" in stylesheet
    assert ".recent-runs-popover{position:absolute;top:calc(100% + 9px);right:0;left:auto;width:min(320px,calc(100vw - 24px));max-height:280px" in stylesheet
    assert ".recent-runs-popover li::before,.recent-runs-popover li::after" in stylesheet
    assert ".recent-runs-popover li>b{border:0!important;border-radius:3px!important" in stylesheet
    assert ".recent-runs-popover li>span{width:auto!important;height:auto!important;border-radius:0!important;background:transparent!important" in stylesheet
    assert 'id="healthDot"' not in html
    assert '<i class="${statusClass}"' not in javascript
    assert ".recent-runs-popover li>i" not in stylesheet
    assert "#healthDot" not in stylesheet


def test_dashboard_uses_top_filters_and_responsive_workspace_navigation():
    html = Path("dashboard/index.html").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert 'class="app-shell"' in html
    assert 'id="filterToggle"' in html
    assert 'id="filterBar"' in html
    assert 'aria-label="Primary views"' in html
    navigation = html.split('<nav id="primaryNavigation"', 1)[1].split("</nav>", 1)[0]
    assert "<small>" not in navigation
    assert 'id="navToggle"' in navigation
    assert 'class="nav-icon"' in navigation
    assert ".app-shell{width:100%;max-width:none!important" in stylesheet
    assert "body.nav-collapsed .app-shell{grid-template-columns:64px" in stylesheet
    assert ".story-nav{position:sticky!important" in stylesheet
    assert "@media(max-width:780px)" in stylesheet
    assert ".filterbar{display:grid!important" in stylesheet
    assert ".filter-toggle[aria-expanded=\"true\"]::before" in stylesheet
    assert '"expandedByDefault": false' in configuration
    assert "showExperimentalEndpoints: false" in configuration


def test_primary_navigation_clears_selected_work_item_between_views():
    javascript = Path("dashboard/app.js").read_text()
    activate_view = javascript.split("function activateView(view){", 1)[1].split("\n}", 1)[0]

    assert "const viewChanged=state.activeView!==view;" in activate_view
    assert "if(viewChanged)clearSelectedWorkItem();" in activate_view
    assert activate_view.index("if(viewChanged)clearSelectedWorkItem();") < activate_view.index("state.activeView=view;render();")


def test_reporting_exposes_customer_workflow_help():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()
    workflow = Path("docs/daily-vulnerability-remediation-workflow.md").read_text()

    assert 'id="openWorkflowHelp"' in html
    assert 'data-view="help"' in html
    assert 'class="nav-help-group"' not in html
    assert 'class="nav-help-heading"' not in html
    assert 'id="help" class="story workflow-help-story"' in html
    assert "How to use this dashboard" in html
    assert "Common customer scenarios" in html
    assert "Read the numbers correctly" in html
    assert '$("openWorkflowHelp").addEventListener("click",()=>activateView("help"))' in javascript
    assert ".workflow-help-story .workflow-help-body{padding:0}" in stylesheet
    assert "Reporting" in workflow
    assert "## Common operating scenarios" in workflow


def test_data_evidence_is_a_separate_diagnostic_page():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    evidence_html = Path("dashboard/data-evidence.html").read_text()
    evidence_javascript = Path("dashboard/data-evidence.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "data-browser" not in html
    assert "dataBrowser" not in javascript
    assert "View evidence" not in javascript
    assert "Diagnostic Data Evidence" in evidence_html
    assert 'id="dataBrowserDataset"' in evidence_html
    assert 'id="dataBrowserTable"' in evidence_html
    assert 'id="dataBrowserJson"' in evidence_html
    assert "/api/data-browser/catalog" in evidence_javascript
    assert "/api/data-browser/${encodeURIComponent(state.dataset)}" in evidence_javascript
    assert "No datasets available" in evidence_javascript
    assert ".story-nav button[hidden]{display:none!important}" in stylesheet


def test_cost_calculator_is_local_only():
    deploy_script = Path("infra/deploy.sh").read_text()
    calculator = Path("tools/calculator.html").read_text()
    readme = Path("README.md").read_text()

    assert Path("tools/calculator.html").is_file()
    assert not Path("dashboard/calculator.html").exists()
    assert "'dashboard/calculator.html'" in deploy_script
    assert "'dashboard/tools/*'" in deploy_script
    assert 'id="tfvarsFile"' in calculator
    assert 'id="functionMemory"' not in calculator
    assert 'id="collectorHourlyRate"' in calculator
    assert 'id="billingHours"' in calculator
    assert 'id="manifestFile"' in calculator
    assert 'id="publishedFiles"' in calculator
    assert 'id="appServiceTier"' in calculator
    assert 'id="existingHistoryGib"' in calculator
    assert 'id="runSizeGib"' in calculator
    assert 'id="retentionModel"' in calculator
    assert 'id="modeledRetentionDays"' in calculator
    assert 'id="immutabilityDays"' in calculator
    assert 'id="annualTotal"' in calculator
    assert 'id="extraWritesPerRun"' in calculator
    assert 'id="extraReadsPerRun"' in calculator
    assert 'id="checkpointGib"' in calculator
    assert 'id="failedRunGib"' in calculator
    assert 'id="workflowEvents"' in calculator
    assert 'id="runtimeStorageGib"' in calculator
    assert 'id="logsPerCollectionGib"' in calculator
    assert 'id="chargeableLogRetentionGib"' in calculator
    assert 'id="egressGib"' in calculator
    assert 'id="licenseCost"' in calculator
    assert "collectionsFromSchedule" in calculator
    assert 'value="B2" selected>B2' in calculator
    assert 'id="collectionsPerDay" type="number" min="0" step=".1" value="1"' in calculator
    assert 'value("collectorHourlyRate")*value("billingHours")' in calculator
    assert 'readLocalFile("manifestFile","manifestStatus",loadManifest)' in calculator
    assert "reader.readAsText(file)" in calculator
    assert "fetch(" not in calculator
    assert "XMLHttpRequest" not in calculator
    assert "The application does not delete retained raw or curated evidence." in calculator
    assert "The bounded option is hypothetical only: it never configures deletion" in calculator
    assert "[Azure cost calculator](tools/calculator.html)" in readme
    assert "Every deployed Azure resource can incur charges." in readme
    assert "[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/)" in readme
