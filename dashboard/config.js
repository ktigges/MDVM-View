/**
 * Author: Kevin Tigges
 * Last modified: 2026-10-08
 * Purpose: Configure dashboard version, presentation, filters, and diagnostic labels.
 */

window.VULNERABILITY_VIEW_CONFIG = {
  version: "2026.10.08.1",
  revision: "2026-10-08T14:57:00Z",
  branding: {
    eyebrow: "VULNERABILITY VIEW",
    title: "Microsoft Vulnerability Management",
  },
  theme: {
    primary: "#0b2f4f",
    accent: "#24a5b7",
    density: "comfortable",
  },
  navigation: {
    order: ["executive", "recommendations", "priority", "overview", "workstations", "sla", "trend", "data-browser"],
    hidden: [],
  },
  filters: {
    expandedByDefault: false,
    defaultSeverity: "All",
    defaultHideNonReporting: false,
    defaultReportingDays: 30,
    defaultIncludeDiscoveredOnly: false,
    defaultRecommendationTypes: ["Vulnerability"],
    defaultDomains: ["Devices", "Cloud"],
  },
  diagnostics: {
    showExperimentalEndpoints: false,
  },
  authentication: {
    showStatus: true,
  },
  workloadGrouping: {
    rules: [
      {
        id: "generated-scale-hosts",
        label: "Generated scale workload",
        field: "DeviceName",
        operator: "prefix",
        value: "gen-",
      },
    ],
  },
};
