import copy

import pytest

from vulnerability_view.normalizer import apply_sla_environment_overrides


def _policy():
    return {
        "schemaVersion": 1,
        "policyVersion": "vulnerability-view-2026-11-14",
        "complianceTargetPercent": 85,
        "lifecycle": {"fixedConfirmationRuns": 1, "deviceFreshnessHours": 168},
        "policies": [
            {"policyName": "CriticalKnownExploit", "severity": "Critical", "knownExploitRequired": True, "slaDays": 14},
            {"policyName": "Critical", "severity": "Critical", "knownExploitRequired": False, "slaDays": 14},
            {"policyName": "High", "severity": "High", "knownExploitRequired": False, "slaDays": 30},
            {"policyName": "Medium", "severity": "Medium", "knownExploitRequired": False, "slaDays": 90},
            {"policyName": "Low", "severity": "Low", "knownExploitRequired": False, "slaDays": 180},
        ],
    }


def _days(policy):
    return {row["policyName"]: row["slaDays"] for row in policy["policies"]}


def test_no_settings_keeps_the_packaged_policy():
    assert apply_sla_environment_overrides(_policy(), {}) == _policy()


def test_settings_override_days_and_record_the_change_in_the_version():
    result = apply_sla_environment_overrides(_policy(), {"SLA_DAYS_HIGH": "45", "SLA_DAYS_LOW": " 200 ", "UNRELATED": "x"})
    assert _days(result) == {"CriticalKnownExploit": 14, "Critical": 14, "High": 45, "Medium": 90, "Low": 200}
    assert result["policyVersion"] == "vulnerability-view-2026-11-14+env-High45-Low200"


def test_known_exploit_policy_uses_snake_case_setting_name():
    result = apply_sla_environment_overrides(_policy(), {"SLA_DAYS_CRITICAL_KNOWN_EXPLOIT": "7"})
    assert _days(result)["CriticalKnownExploit"] == 7
    assert _days(result)["Critical"] == 14
    assert result["policyVersion"].endswith("+env-CriticalKnownExploit7")


@pytest.mark.parametrize("environ", [{"SLA_DAYS_HIGH": "30"}, {"SLA_DAYS_HIGH": "   "}, {"SLA_DAYS_HIGH": ""}])
def test_same_or_blank_value_is_not_a_change(environ):
    assert apply_sla_environment_overrides(_policy(), environ) == _policy()


@pytest.mark.parametrize("value", ["0", "abc", "3651", "-5", "1.5"])
def test_invalid_days_fail_the_run_visibly(value):
    with pytest.raises(ValueError, match="SLA_DAYS_HIGH"):
        apply_sla_environment_overrides(_policy(), {"SLA_DAYS_HIGH": value})


def test_input_policy_is_not_mutated():
    policy = _policy()
    original = copy.deepcopy(policy)
    apply_sla_environment_overrides(policy, {"SLA_DAYS_CRITICAL": "3"})
    assert policy == original
