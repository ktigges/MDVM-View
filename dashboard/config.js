/**
 * Author: Kevin Tigges
 * Last modified: 2026-11-05
 * Purpose: Configure dashboard version, presentation, filters, and diagnostic labels.
 */

window.VULNERABILITY_VIEW_DEFAULTS = {
  "filters": {
    "expandedByDefault": false,
    "defaultSeverity": "All",
    "defaultHideNonReporting": false,
    "defaultReportingDays": 30,
    "defaultIncludeDiscoveredOnly": false,
    "defaultRecommendationTypes": ["Vulnerability"],
    "defaultDomains": ["Devices", "Cloud"]
  },
  "workloadGrouping": {
    "rules": [
      {
        "id": "generated-scale-hosts",
        "label": "Generated scale workload",
        "field": "DeviceName",
        "operator": "prefix",
        "value": "gen-"
      }
    ]
  }
};

window.VULNERABILITY_VIEW_CONFIG = {
  version: "2026.11.14.2",
  revision: "2026-11-14T08:48:03Z",
  branding: {
    eyebrow: "VULNERABILITY VIEW",
    title: "Microsoft Vulnerability Management",
    customerLogo: {
      enabled: false,
      src: "customer-logo.svg",
      alt: "Customer logo",
    },
  },
  theme: {
    primary: "#0b2f4f",
    accent: "#24a5b7",
    density: "comfortable",
  },
  navigation: {
    order: ["executive", "overview", "recommendations", "workstations", "slaDashboard", "trend", "executiveSnapshot", "jobHistory"],
    hidden: [],
  },
  filters: window.VULNERABILITY_VIEW_DEFAULTS.filters,
  diagnostics: {
    showExperimentalEndpoints: false,
  },
  authentication: {
    showStatus: true,
  },
  workloadGrouping: window.VULNERABILITY_VIEW_DEFAULTS.workloadGrouping,
};
