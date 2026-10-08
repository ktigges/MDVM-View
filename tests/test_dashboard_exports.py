"""Last modified: 2026-10-08.
Purpose: Verify dashboard exports, presentation contracts, versioning, and local-only tools.
"""

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


def test_dashboard_loads_datasets_progressively():
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert "loadDashboardDatasets" in javascript
    assert "rebuildDerivedState" in javascript
    assert "datasets ready" in javascript
    assert "Promise.all(" not in javascript
    assert ".loading-notice.degraded" in stylesheet


def test_dashboard_filter_workspace_has_distinct_shading():
    html = Path("dashboard/index.html").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()
    final_toolbar_rule = [rule for rule in re.findall(r"\.filter-toolbar\{([^}]*)\}", stylesheet) if "background:" in rule][-1]
    final_filterbar_rule = [rule for rule in re.findall(r"\.filterbar\{([^}]*)\}", stylesheet) if "background:" in rule][-1]

    assert html.index('id="scopeBar"') < html.index('class="filter-toolbar"')
    assert "background:#d9dde1!important" in final_toolbar_rule
    assert "background:#adb7bd!important" in final_filterbar_rule
    assert "box-shadow:inset 0 1px 0" in final_toolbar_rule
    assert "box-shadow:0 16px 30px" in final_filterbar_rule
    assert 'class="filter-check-options"' in html
    assert "background-color:#cdd4d8!important" in stylesheet
    assert "background:#c7cfd3" in stylesheet
    assert ".filterbar fieldset{display:grid!important" in stylesheet
    assert "border:0!important" in stylesheet
    assert "background:#17384f!important" in stylesheet
    assert "border-left:5px solid var(--cyan)!important" in stylesheet
    assert "@media(max-width:1450px)" in stylesheet
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


def test_recommendation_preview_is_anchored_to_hovered_row():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="recommendationPreview" class="recommendation-preview" role="status" hidden' in html
    assert "row.getBoundingClientRect()" in javascript
    assert "preview.style.left" in javascript
    assert "preview.style.top" in javascript
    assert 'row.addEventListener("mouseleave",hide)' in javascript
    assert 'row.addEventListener("blur",hide)' in javascript
    assert "max-height:calc(100vh - 24px)" in stylesheet
    assert html.index('id="recommendationPreview"') > html.index("</main>")
    assert ".recommendation-preview{display:none!important}" not in stylesheet
    assert 'bindRecommendationPreviews("recommendationTable"' in javascript
    assert 'bindRecommendationPreviews("priorityTable"' in javascript
    assert 'bindRecommendationPreviews("remediationOutcomeTable"' in javascript
    assert 'bindRecommendationPreviews("remediationTable"' in javascript


def test_dashboard_distinguishes_sla_targets_and_task_due_dates():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "Selected-period finding results against severity-based SLA targets" in html
    assert 'id="slaPolicySummary"' in html
    assert 'fetch("/api/sla-policy")' in javascript
    assert "Current dataset policy" in javascript
    assert "Targets start at the collector's first observation" in javascript
    assert "Weekly remediation task due-date history" in html
    assert "Recommendation inventory and workflow" in html
    assert "Risk-ranked work queue ordered by effective severity" in html
    assert "Highest linked open-finding severity combined with Defender recommendation score" in html


def test_dashboard_orders_all_recommendation_surfaces_highest_first():
    javascript = Path("dashboard/app.js").read_text()

    assert "const SEVERITY_RANK={Critical:4,High:3,Medium:2,Low:1}" in javascript
    assert "function compareRecommendations(a,b)" in javascript
    assert "row.RecommendationSeverity||recommendationSeverity(row)" in javascript
    assert "recommendationSeverity(row,impact.rows)" in javascript
    assert "recommendationSeverity(row,linked)" in javascript
    assert "state.recommendations.filter(recommendationMatches).sort(compareRecommendations)" in javascript
    assert '.filter(row=>state.severity==="All"||row.RecommendationSeverity===state.severity).sort(compareRecommendations)' in javascript
    assert "recommendationImpactRows(recommendations).filter(row=>row.OpenFindings>0).slice(0,limit)" in javascript
    assert "state.detailRecommendationIds=[...new Set(filteredRecommendations().map" in javascript


def test_dashboard_groups_scale_out_instances_as_configurable_workloads():
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert "function remediationWorkload(row)" in javascript
    assert "virtualMachineScaleSets" in javascript
    assert "function configuredWorkload(row)" in javascript
    assert "function actionableWorkloadCount(rows)" in javascript
    assert 'id: "generated-scale-hosts"' in configuration
    assert 'operator: "prefix"' in configuration
    assert 'value: "gen-"' in configuration
    assert '"ActionableWorkloads"' in javascript
    assert '"WorkloadType","InstanceCount"' in javascript


def test_dashboard_exposes_shared_recommendation_work_status_filter():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "Recommendation work status" in html
    assert "Shared status; filtering does not assign or lock work" in html
    assert '<option value="InProgress">In progress</option>' in html
    assert '<option value="NeedsReassignment">Needs reassignment</option>' in html
    assert '<option value="Untracked">Untracked / not started</option>' in html
    assert 'recommendationTrackingFilter:"All"' in javascript
    assert "TrackingUpdatedBy" in javascript
    assert "TrackingUserId" in javascript
    assert "TrackingUpdatedUtc" in javascript
    assert "Last updated by ${tracking.updatedByDisplayName}" in javascript
    assert "recommendationWorkStatus" in javascript
    assert 'const columns=["RecommendationName","RecommendationSeverity"' in javascript
    assert "recommendationTrackingLocalPreview" in javascript
    assert "recommendationWorkSwitch" not in javascript
    assert 'aria-label="Working here:' not in javascript
    assert "Use the compact ON/OFF switch" not in html
    assert "Open a recommendation to update its dashboard work status" in html


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
    assert ".freshness strong{font-size:16px!important" in stylesheet
    assert ".header-status-item{padding:9px 11px!important;font-size:12px!important}" in stylesheet
    assert ".app-shell{grid-template-columns:220px minmax(0,1fr)!important}" in stylesheet
    assert ".story-nav button span{font-size:15px!important" in stylesheet
    assert ".scope-bar strong{font-size:17px!important}" in stylesheet
    assert ".scope-bar p{font-size:14px!important" in stylesheet
    assert ".filter-toolbar #filterCount{font-size:13px!important}" in stylesheet


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
    assert "Findings fixed within policy SLA" in javascript
    assert "Findings fixed outside policy SLA" in javascript
    assert "FixedFindings:0,OpenFindings:0" in javascript
    assert "fixed on ${fmt(item.fixedMachines.size)} machine" in javascript
    assert "remain open on ${fmt(item.openMachines.size)} machine" in javascript
    assert "View machines and CVEs" in javascript
    assert "recommendationMachineEvidence" in javascript
    assert "Remediated UTC" in javascript
    assert "Latest remediated UTC" in javascript
    assert "machine-evidence-header" in javascript
    assert "Currently open machines" in javascript
    assert "select one to see its CVEs" in javascript
    assert "Machines with fixes" in javascript
    assert "Machines still exposed" in javascript


def test_dashboard_treats_remediation_activity_as_supporting_context():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "GLOBAL VULNERABILITY SLA · FINDING-LEVEL RESULTS" in html
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


def test_dashboard_orders_remediation_by_priority():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "Highest effective severity, then current things to fix" in html
    assert "Active first, then task priority, overdue state, and due date" in html
    assert '["RecommendationSeverity","SeverityScore","RecommendationName"' in javascript
    assert ".sort((a,b)=>compareRecommendations(a,b)||(b.NewToday+b.ReopenedToday)" in javascript
    assert "const priorityRank={critical:4,high:3,medium:2,low:1}" in javascript


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
    assert "Open findings · before latest refresh" in javascript
    assert "Findings fixed · latest refresh" in javascript
    assert "BeforeToCurrent" in javascript
    assert "showRecommendationOutcome" in javascript
    assert "View machines and CVEs" in javascript
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
    assert '<button data-view="trend"><span>Reporting</span></button>' in html
    assert "<h2>Vulnerability reporting and change over time</h2>" in html
    assert 'id="statisticsPeriod"' in html
    assert "This week vs previous week" in html
    assert "Latest run vs previous run" in html
    assert "Custom range vs preceding equal range" in html
    assert 'id="statisticsSlaBreakdown"' in html
    assert "Selected-period finding results against severity-based SLA targets" in html
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


def test_dashboard_can_hide_devices_outside_a_snapshot_relative_reporting_window():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()

    assert 'id="hideNonReporting" type="checkbox"' in html
    assert 'id="reportingDays"' in html
    for days in (7, 14, 30, 60, 90):
        assert f'value="{days}">Last reported within {days} days' in html
    assert "defaultHideNonReporting: false" in configuration
    assert "defaultReportingDays: 30" in configuration
    assert "datasetSnapshotMs" in javascript
    assert "row.LastSeenUtc" in javascript
    assert "snapshot-state.reportingDays*86400000" in javascript
    assert "reportingMatches(row)" in javascript
    assert "reportingLinked=linked.filter(reportingMatches)" in javascript
    assert "linked=(state.findingsByRecommendation.get(id)||[]).filter(reportingMatches)" in javascript
    assert "machineInScope=row=>" in javascript
    assert "subscriptionMatches(row)&&reportingMatches(row)" in javascript
    assert "function trendScopedFindings()" in javascript
    assert "item.DeviceId===row.DeviceId&&item.DataOrigin===row.DataOrigin&&reportingMatches(item)" in javascript
    assert 'state.hideNonReporting=Boolean(filterConfig.defaultHideNonReporting)' in javascript
    assert '`Within ${state.reportingDays} days`' in javascript


def test_attention_required_vulnerability_recommendations_remain_in_vulnerability_scope():
    javascript = Path("dashboard/app.js").read_text()

    assert r"/\bvulnerabilit(?:y|ies)\b/.test(text)" in javascript
    assert '`${row.RecommendationName||""} ${row.SubCategory||""}`' in javascript


def test_dashboard_carries_remediation_outcomes_into_weekly_history():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert "periodRemediationOutcome" in javascript
    assert 'id="statisticsPeriodCards"' in html
    assert 'id="statisticsPeriodTable"' in html
    assert '["Week","Days","New","Fixed","AssetsRemediated","FindingsResolved","RemediationResult"' in javascript
    assert "Net finding change" in javascript
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
    assert '{name:"subscriptions",key:"subscriptions",label:"subscriptions",required:false}' in javascript
    assert "state.subscriptionInventoryById" in javascript
    assert "subscription.SubscriptionName" in javascript


def test_dashboard_asset_inventory_uses_devices_and_includes_cloud_assets_without_findings():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert '<button data-view="workstations"><span>Assets</span></button>' in html
    assert "<h2>Asset inventory</h2>" in html
    assert "including assets with no current vulnerability rows" in html
    assert '{name:"devices",key:"devices",label:"device inventory",required:true}' in javascript
    assert "state.devices.filter(device=>inventoryDeviceMatches(device)" in javascript
    assert 'state.domains.has(findingDomain(row))' in javascript
    assert 'id="includeDiscoveredAssets" type="checkbox"' in html
    assert "defaultIncludeDiscoveredOnly: false" in Path("dashboard/config.js").read_text()
    assert 'state.includeDiscoveredOnly||device.OnboardingStatus==="Onboarded"' in javascript
    assert 'coverage=assessed?"Endpoint assessed":item.OpenFindings?"Limited evidence":"Not assessed"' in javascript
    assert '["OpenFindings","Critical","High","Medium","Low"].includes(column)&&row.VulnerabilityCoverage==="Not assessed"' in javascript
    assert '["DeviceName","WorkloadType","InstanceCount","OSPlatform","AssetClass","Subscription","HealthStatus","OnboardingStatus","VulnerabilityCoverage","LastSeenUtc","OpenFindings","Critical","High","Medium","Low"]' in javascript


def test_dashboard_has_severity_based_finding_and_recommendation_sla_graphs():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()

    assert 'id="findingSlaGraph"' in html
    assert 'id="recommendationSlaGraph"' in html
    assert 'id="statisticsSlaCards"' in html
    assert 'id="statisticsSlaBreakdown"' in html
    assert "Finding outcomes by severity" in html
    assert "Selected-period finding results against severity-based SLA targets" in html
    assert "Recommendation outcomes by severity" in html
    assert "findingSlaSeverityRows" in javascript
    assert "recommendationSlaSeverityRows" in javascript
    assert 'row.SlaStatus==="OpenWithinSla"' in javascript
    assert "Open findings within SLA" in javascript
    assert "Open findings overdue" in javascript
    assert "Findings fixed within SLA" in javascript
    assert "Findings fixed outside SLA" in javascript
    assert "Recommendations with overdue findings" in javascript


def test_dashboard_reports_latest_run_executive_deltas():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    stylesheet = Path("dashboard/styles.css").read_text()

    assert 'id="executiveDeltaContext"' in html
    assert '{name:"finding-events",key:"findingEvents",label:"finding history",required:false}' in javascript
    assert "comparableRunSnapshots" in javascript
    assert "since previous run" in javascript
    assert "New findings since previous run" in javascript
    assert "Findings fixed since previous run" in javascript
    assert 'label:"Open recommendations"' in javascript
    assert "metric-delta" in javascript
    assert ".metric-delta.good" in stylesheet
    assert ".metric-delta.bad" in stylesheet


def test_statistics_view_is_presented_as_reporting():
    html = Path("dashboard/index.html").read_text()

    assert '<button data-view="trend"><span>Reporting</span></button>' in html
    assert "Vulnerability reporting and change over time" in html
    assert "Workload and SLA statistics" not in html
    assert "New findings" in html
    assert "Ending open findings" in html


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
    assert "setTimeout(()=>show(index,row,event.clientX),350)" in javascript
    assert html.index('id="recommendationPreview"') > html.index("</main>")
    assert "RECOMMENDATION INVENTORY" not in html
    assert "<h2>Recommendation inventory and workflow</h2>" in html
    assert 'selectEntity("recommendation",id,true)' in javascript
    assert 'order: ["executive", "recommendations", "priority", "overview", "workstations", "sla", "trend", "data-browser"]' in configuration


def test_dashboard_shows_ui_revision_below_live_snapshot():
    html = Path("dashboard/index.html").read_text()
    javascript = Path("dashboard/app.js").read_text()
    configuration = Path("dashboard/config.js").read_text()
    deployment = Path("infra/deploy.sh").read_text()

    assert "Live snapshot" in html
    assert 'id="revisionText"' in html
    assert "formatUtc" in javascript
    assert "UI revision ${presentation.revision?formatUtc(presentation.revision)" in javascript
    assert "latest?formatUtc(latest.SnapshotTimeUtc)" in javascript
    assert re.search(r'version: "\d{4}\.\d{2}\.\d{2}\.\d+"', configuration)
    assert re.search(r'revision: "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"', configuration)
    assert 'ui_revision="$(date -u' in deployment
    assert "Packaged dashboard version $dashboard_version, UI revision $ui_revision" in deployment
    assert "Could not stamp all dashboard asset versions" in deployment


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
def test_cost_calculator_is_local_only():
    deploy_script = Path("infra/deploy.sh").read_text()
    calculator = Path("tools/calculator.html").read_text()

    assert Path("tools/calculator.html").is_file()
    assert not Path("dashboard/calculator.html").exists()
    assert "'dashboard/calculator.html'" in deploy_script
    assert "'dashboard/tools/*'" in deploy_script
    assert 'id="tfvarsFile"' in calculator
    assert 'id="functionMemory"' in calculator
    assert 'id="appServiceTier"' in calculator
    assert 'id="existingHistoryGib"' in calculator
    assert 'id="runSizeGib"' in calculator
    assert 'id="retentionModel"' in calculator
    assert 'id="modeledRetentionDays"' in calculator
    assert 'id="immutabilityDays"' in calculator
    assert 'id="annualTotal"' in calculator
    assert 'id="writesPerRun"' in calculator
    assert 'id="workflowEvents"' in calculator
    assert 'id="runtimeStorageGib"' in calculator
    assert 'id="logsPerCollectionGib"' in calculator
    assert 'id="chargeableLogRetentionGib"' in calculator
    assert 'id="egressGib"' in calculator
    assert 'id="licenseCost"' in calculator
    assert "collectionsFromSchedule" in calculator
    assert "The application does not delete retained raw or curated evidence." in calculator
    assert "The bounded option changes estimates only; it does not configure deletion." in calculator
