"""Compare server aggregates with the dashboard's existing lifecycle helpers."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vulnerability_view.dashboard_queries import DashboardQueryEngine


SNAPSHOT = "2026-10-24T00:59:46Z"


def legacy_metrics(rows):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for cross-runtime dashboard parity")
    script = r"""
const fs=require("node:fs"),vm=require("node:vm");
const source=fs.readFileSync("dashboard/app.js","utf8").split("\n");
const rows=JSON.parse(fs.readFileSync(0,"utf8"));
const context=vm.createContext({
  PENDING_FINDING_STATUSES:new Set(["PendingConfirmation","PendingVerification"]),
  DETECTED_FINDING_STATUSES:new Set(["Open","Reopened","DetectionReturned"]),
  state:{search:""},
});
for(const name of ["truthy","pending","detected","slaResolved"])
  vm.runInContext(source.find(line=>line.startsWith(`const ${name}=`)),context);
for(const name of ["normalizedCve","findingKnownExploit","aggregateBy","rowCounts","cveRowsFor","slaCardItems","matchesSearch"])
  vm.runInContext(source.find(line=>line.startsWith(`function ${name}(`)),context);
const cves=context.cveRowsFor(rows).map(row=>{
  const {rows,...result}=row;
  const detected=vm.runInContext("detected",context);
  return {...result,EvidenceRows:rows.length,DetectedMachines:new Set(rows.filter(detected).map(row=>row.DeviceId).filter(Boolean)).size};
});
const searches={};
for(const search of ["%","_","null","none","findingkey","münchen","CVE-2026-1001"]){
  context.state.search=search.toLowerCase();
  searches[search]=rows.filter(context.matchesSearch).map(row=>row.FindingKey).sort();
}
console.log(JSON.stringify({cards:context.slaCardItems(rows),cves,searches}));
"""
    result = subprocess.run(
        [node, "-e", script], input=json.dumps(rows), text=True,
        capture_output=True, timeout=15, cwd=Path(__file__).parents[1],
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_server_preserves_cve_and_sla_lifecycle_arithmetic(tmp_path):
    common = {
        "DataOrigin": "Live", "AssetClass": "TraditionalIT", "OwnerTeam": "Endpoints",
        "SubscriptionId": "", "SnapshotTimeUtc": SNAPSHOT, "LastSeenUtc": SNAPSHOT,
        "RecommendationId": "rec-1", "FirstObservedUtc": "2026-10-23T01:00:00Z",
        "CveId": "CVE-2026-1001", "Severity": "High", "CvssScore": 8.8,
        "PublicExploitAvailable": False,
        "DeviceName": "", "NullableField": None,
    }
    variants = [
        {"FindingStatus": "Open", "SlaStatus": "OpenOutsideSla", "DeviceId": "a", "DeviceName": "MÜNCHEN_100%"},
        {"FindingStatus": "Reopened", "SlaStatus": "OpenWithinSla", "DeviceId": "a"},
        {"FindingStatus": "PendingConfirmation", "SlaStatus": "FixedWithinSla",
         "EffectiveRemediationUtc": "2026-10-23T12:00:00Z", "DeviceId": "b"},
        {"FindingStatus": "PendingVerification", "SlaStatus": "FixedOutsideSla", "DeviceId": "c"},
        {"FindingStatus": "Fixed", "SlaStatus": "FixedOutsideSla",
         "FixedUtc": "2026-10-23T12:00:00Z", "DeviceId": "d"},
        {"FindingStatus": "DetectionReturned", "SlaStatus": "OpenWithinSla", "DeviceId": "e",
         "CveId": "CVE-2026-1002", "PublicExploitAvailable": True},
        {"FindingStatus": "StaleDevice", "SlaStatus": "Unknown", "DeviceId": "f",
         "CveId": "CVE-2026-1002", "PublicExploitAvailable": True},
    ]
    findings = [{**common, **row, "FindingKey": f"finding-{index}"} for index, row in enumerate(variants)]
    datasets = {
        "findings": findings,
        "recommendations": [{
            "RecommendationId": "rec-1", "RecommendationName": "Update software",
            "RemediationType": "Update", "DataOrigin": "Live",
        }],
        "collection-runs": [{"CollectionRunId": "run-a", "SnapshotTimeUtc": SNAPSHOT, "DataOrigin": "Live"}],
    }

    def rows(name):
        return iter(datasets.get(name, []))

    engine = DashboardQueryEngine(tmp_path, "parity", SNAPSHOT, rows)
    request = {
        "filters": {"exposureStatus": "All", "origin": "Both", "severity": "All",
                    "domains": ["Devices", "Cloud"], "recommendationTypes": ["Vulnerability"]},
        "page": 0, "limit": 100,
    }
    expected = legacy_metrics(findings)
    overview = engine.query({**request, "view": "overview", "mode": "cves"})
    actual = overview["tables"]["findingsTable"]["items"]
    fields = [
        "CveId", "Severity", "CvssScore", "KnownExploit", "OpenFindings",
        "PendingFindings", "FixedFindings", "DetectedMachines", "EvidenceRows",
    ]
    assert [{field: row[field] for field in fields} for row in actual] == [
        {field: row[field] for field in fields} for row in expected["cves"]
    ]
    sla = engine.query({**request, "view": "sla"})
    assert sla["cards"]["slaCards"] == expected["cards"]
    for search, keys in expected["searches"].items():
        result = engine.query({
            **request, "view": "overview", "mode": "findings",
            "filters": {**request["filters"], "search": search.lower()},
        })
        page = result["tables"]["findingsTable"]
        assert page["total"] == len(keys), search
        assert sorted(row["FindingKey"] for row in page["items"]) == keys, search
