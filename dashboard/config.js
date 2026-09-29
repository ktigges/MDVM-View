/**
 * Author: Kevin Tigges
 * Last modified: 2026-09-27
 * Purpose: Configure dashboard presentation, filters, and diagnostic labels.
 */

window.VULNERABILITY_VIEW_CONFIG = {
  revision: "2026-09-28T23:16:21Z",
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
