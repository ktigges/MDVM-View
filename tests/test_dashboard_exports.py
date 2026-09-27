import csv
import json
import re
from pathlib import Path

from vulnerability_view.dataprep_cli import build_synthetic
from vulnerability_view.config import Settings
from vulnerability_view.export_writer import write_outputs


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
    assert "renderAvailability" in javascript
    assert "Defender snapshot" in javascript
    assert 'id="developmentWarning"' in html
    assert "localDevelopmentOnly" in javascript
    assert ".development-warning" in stylesheet


def test_dashboard_uses_microsoft_vulnerability_management_branding():
    html = Path("dashboard/index.html").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "<title>Microsoft Vulnerability Management</title>" in html
    assert "<h1>Microsoft Vulnerability Management</h1>" in html
    assert 'class="ms-logo"' in html
    assert ".brand-title" in stylesheet
    assert "#f25022" in stylesheet


def test_dashboard_severity_sla_drilldown_contract():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "Remediation position" not in html
    assert "Current SLA state in this filter context" not in html
    assert all(
        element_id in html
        for element_id in (
            'id="executiveSlaBreakdown"',
            'id="statisticsSlaBreakdown"',
        )
    )
    assert "showSlaSeverityDetail" in javascript
    assert "sla-severity-link" in javascript
    assert "Policy SLA fixed within" in javascript
    assert "Policy SLA fixed outside" in javascript


def test_dashboard_treats_remediation_activity_as_supporting_context():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "GLOBAL VULNERABILITY SLA · FINDING CLOCK" in html
    assert 'id="weeklyTaskDueTable"' in html
    assert "Remediation history" in html
    assert "Remediation activity context" in html
    assert "Remediation activities are supporting context" in html
    assert 'id="remediateTaskDueBreakdown"' not in html
    assert "taskDueStatus" in javascript
    assert "CompletedByDueDate" in javascript
    assert "CompletedAfterDueDate" in javascript
    assert "PolicySLAWithin" in javascript
    assert "PolicySLAOutside" in javascript
    assert "renderStatisticsPeriod" in javascript

def test_dashboard_shows_endpoint_remediation_impact():
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "endpointRemediationImpact" in javascript
    assert "ENDPOINT REMEDIATION IMPACT" in javascript
    assert "Before" in javascript
    assert "Fixed today" in javascript
    assert "Current" in javascript
    assert "Delta" in javascript
    assert ".endpoint-impact" in stylesheet


def test_dashboard_exposes_workstation_and_recommendation_outcomes():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'data-view="workstations"' in html
    assert 'id="workstationTable"' in html
    assert "Operating queue (derived)" in html
    assert "Inferred from asset evidence, not a Defender assignment" in html
    assert 'id="scopeBar"' in html
    assert 'id="resetFilters"' in html
    assert 'id="remediationOutcomeTable"' in html
    assert "renderWorkstations" in javascript
    assert "renderRemediationOutcomes" in javascript
    assert "Things to fix · before latest refresh" in javascript
    assert "Confirmed fixed · latest refresh" in javascript
    assert "BeforeToCurrent" in javascript
    assert "showRecommendationOutcome" in javascript
    assert "View remediation outcome" in javascript
    assert "FixedDevicesToday" in javascript
    assert "FindingsFixedToday" in javascript
    assert "Remaining exposed machines" in javascript
    assert "remediationResult" in javascript
    assert "Remediated ${fmt(assets)} asset" in javascript
    assert "CurrentThingsToFix" in javascript
    assert "RemediationResult" in javascript
    assert "Remediation started" in javascript


def test_dashboard_prioritizes_recommendations_not_individual_findings():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "<h2>Prioritized recommendations</h2>" in html
    assert "priorityRecommendationRows" in javascript
    assert "renderPriority" in javascript
    assert "RecommendationSeverity" in javascript
    assert "AffectedMachines" in javascript
    assert "RelatedCves" in javascript
    assert "RemediationStarted" in javascript
    assert "Number(b.SeverityScore||0)-Number(a.SeverityScore||0)" in javascript
    assert '["PriorityScore","Severity","CveId"' not in javascript


def test_dashboard_selected_work_item_honors_search_context():
    javascript = Path("dashboard/app.js").read_text()

    assert "linked.some(matchesSearch)||machines.some(matchesSearch)" in javascript
    assert "openRows.filter(item=>String(item.RecommendationId||\"\")===id)" in javascript
    assert "recommendationSearchMatch||matchesSearch(row)" in javascript
    assert "Affected machines" in javascript
    assert "Linked CVEs" in javascript
    assert "No impacted machines match the current filters." in javascript


def test_dashboard_supports_entity_pivots_for_recommendations_cves_and_machines():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="pivotDetails"' in html
    assert "selectedEntity" in javascript
    assert "selectEntity" in javascript
    assert "pivotToRecommendation" in javascript
    assert "pivotToCve" in javascript
    assert "pivotToMachine" in javascript
    assert "renderRecommendationPivot" in javascript
    assert "renderCvePivot" in javascript
    assert "renderMachinePivot" in javascript
    assert "loadCveDetail" in javascript
    assert "/api/data/cve-details/${encodeURIComponent(key)}.json" in javascript
    assert "fetch(`/api/data/${name}.json`)" in javascript
    assert 'load("vulnerabilities")' not in javascript
    assert "CVE detail" in javascript
    assert "Collected from Defender vulnerabilities API" in javascript
    assert "Open vulnerabilities in Defender" in javascript
    assert "Selected: Recommendation" in javascript
    assert "Selected: CVE" in javascript
    assert "Selected: Machine" in javascript
    assert "CVEs affecting this machine across the filtered recommendations" in javascript
    assert "Other CVEs on the same filtered machines" in javascript
    assert ".pivot-details" in stylesheet


def test_dashboard_renders_only_active_heavy_view():
    javascript = Path("dashboard/app.js").read_text()

    assert 'state.activeView==="executive"' in javascript
    assert 'state.activeView==="overview"' in javascript
    assert 'state.activeView==="workstations"' in javascript
    assert 'state.activeView==="trend"' in javascript
    assert "function activateView(view)" in javascript
    assert "state.activeView=view;render();" in javascript


def test_dashboard_opens_cve_detail_dialog_before_pivoting():
    javascript = Path("dashboard/app.js").read_text()

    assert "showCveDetailDialog" in javascript
    assert 'function pivotToCve(row){const id=normalizedCve(row.CveId||row.id||row);if(id)showCveDetailDialog(id);}' in javascript
    assert 'id="dialogCveDetailTable"' in javascript
    assert 'id="dialogCveMachines"' in javascript
    assert 'id="dialogCveRecommendations"' in javascript
    assert 'id="dialogRelatedCves"' in javascript
    assert "Loading Defender vulnerability detail" in javascript
    assert "pivotFromDialog" in javascript


def test_dashboard_uses_statistics_tab_without_ownership_story():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'data-view="trend"' in html
    assert "<h2>Workload and SLA statistics</h2>" in html
    assert 'id="statisticsPeriod"' in html
    assert "This week vs previous week" in html
    assert "Latest run vs previous run" in html
    assert "Custom range vs preceding equal range" in html
    assert 'id="statisticsSlaBreakdown"' in html
    assert "Selected-period SLA against policy due dates" in html
    assert 'data-view="ownership"' not in html
    assert 'id="ownership"' not in html
    assert 'id="assignmentTable"' not in html
    assert "renderOwnership" not in javascript


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
    assert 'defaultRecommendationTypes: ["Vulnerability"]' in configuration
    assert 'defaultDomains: ["Devices", "Cloud"]' in configuration


def test_dashboard_carries_remediation_outcomes_into_weekly_history():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "periodRemediationOutcome" in javascript
    assert 'id="statisticsPeriodCards"' in html
    assert 'id="statisticsPeriodTable"' in html
    assert '["Week","Days","New","Fixed","AssetsRemediated","FindingsResolved","RemediationResult"' in javascript
    assert "Net workload change" in javascript
    assert "Ending open findings" in javascript


def test_dashboard_filters_by_normalized_asset_classification():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'id="assetClassFilter"' in html
    assert '<option value="AzureCloud">Azure / Cloud</option>' in html
    assert '<option value="TraditionalIT">Traditional IT</option>' in html
    assert "Azure resource metadata → Defender machine tag → inventory fallback" in html
    assert "assetClassMatches" in javascript
    assert 'state.assetClass="All"' in javascript
    assert '$("assetClassFilter").value="All"' in javascript


def test_dashboard_filters_all_views_by_subscription():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'id="subscriptionFilter"' in html
    assert "No subscription" in html
    assert "subscriptionMatches" in javascript
    assert 'state.subscription="All"' in javascript
    assert '$("subscriptionFilter").value="All"' in javascript
    assert "SubscriptionId" in javascript
    assert 'load("subscriptions").catch(()=>[])' in javascript
    assert "state.subscriptionInventoryById" in javascript
    assert "subscription.SubscriptionName" in javascript


def test_dashboard_has_severity_based_finding_and_recommendation_sla_graphs():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'id="findingSlaGraph"' in html
    assert 'id="recommendationSlaGraph"' in html
    assert 'id="statisticsSlaCards"' in html
    assert 'id="statisticsSlaBreakdown"' in html
    assert "Finding outcomes by severity" in html
    assert "Selected-period SLA against policy due dates" in html
    assert "Recommendation outcomes by severity" in html
    assert "findingSlaSeverityRows" in javascript
    assert "recommendationSlaSeverityRows" in javascript
    assert 'row.SlaStatus==="OpenWithinSla"' in javascript
    assert "Open within SLA" in javascript
    assert "Open outside SLA" in javascript
    assert "Fixed within SLA" in javascript
    assert "Fixed outside SLA" in javascript


def test_dashboard_shows_severity_and_subscription_coverage_panel():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'id="severityCards"' in html
    assert "Severity and subscription coverage" in html
    assert "severityCardItems" in javascript
    assert "Critical open" in javascript
    assert "High open" in javascript
    assert "Medium open" in javascript
    assert "Low open" in javascript
    assert "Cloud findings" in javascript
    assert "Subscriptions represented" in javascript


def test_dashboard_has_executive_tab_with_donut_visuals():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'data-view="executive"' in html
    assert 'id="executive" class="story active"' in html
    assert "Story 0" not in html
    assert 'id="recommendationSeverityPie"' in html
    assert 'id="findingSeverityPie"' in html
    assert 'id="assetExposurePie"' in html
    assert "renderDonut" in javascript
    assert "recommendationSeverityPie" in javascript
    assert ".donut" in stylesheet


def test_dashboard_connects_executive_workload_sla_and_recommendation_impact():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert 'id="secureScoreCard"' in html
    assert 'id="executiveWorkload"' in html
    assert 'id="executiveSlaPerformance"' in html
    assert 'id="executiveRecommendationImpact"' in html
    assert 'id="recommendationPreview"' in html
    assert 'id="pivotBackdrop"' in html
    assert "latestSecureScore" in javascript
    assert 'row.DataOrigin==="Live"' in javascript
    assert "recommendationImpactRows" in javascript
    assert "VulnerabilityMix" in javascript
    assert "CveExamples" in javascript
    assert "FixImpact" in javascript
    assert "bindRecommendationPreviews" in javascript
    assert "setTimeout(()=>show(index),350)" in javascript
    assert html.index('id="recommendationPreview"') < html.index('class="panel recommendation-inventory"')
    assert "RECOMMENDATION INVENTORY" not in html
    assert "<h2>Recommendations and estimated impact</h2>" in html
    assert 'selectEntity("recommendation",id,true)' in javascript
    assert 'order: ["executive", "recommendations", "priority", "overview", "workstations", "sla", "trend", "data-browser"]' in configuration


def test_dashboard_shows_ui_revision_below_live_snapshot():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert "Live snapshot" in html
    assert 'id="revisionText"' in html
    assert "formatUtc" in javascript
    assert "UI revision ${presentation.revision?formatUtc(presentation.revision)" in javascript
    assert "latest?formatUtc(latest.SnapshotTimeUtc)" in javascript
    assert re.search(r'revision: "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"', configuration)


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
    assert ".app-shell{grid-template-columns:190px" in stylesheet
    assert ".story-nav{position:sticky!important" in stylesheet
    assert "@media(max-width:960px)" in stylesheet
    assert ".filterbar{display:grid!important" in stylesheet
    assert ".filter-toggle[aria-expanded=\"true\"]::before" in stylesheet
    assert "expandedByDefault: false" in configuration
    assert "showExperimentalEndpoints: false" in configuration


def test_dashboard_data_browser_is_hidden_and_read_only_by_default():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'data-view="data-browser" data-feature="data-browser" hidden' in html
    assert 'id="dataBrowserDataset"' in html
    assert 'id="dataBrowserTable"' in html
    assert 'id="dataBrowserJson"' in html
    assert "Read-only evidence" in html
    assert "/api/data-browser/catalog" in javascript
    assert "/api/data-browser/${encodeURIComponent(dataBrowserState.dataset)}" in javascript
    assert "openMetricEvidence" in javascript
    assert "View evidence" in javascript
    assert ".story-nav button[hidden]{display:none!important}" in stylesheet