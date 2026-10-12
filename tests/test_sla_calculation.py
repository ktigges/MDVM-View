import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vulnerability_view.normalizer import apply_sla, load_sla_policies, load_sla_policy_config


UTC = timezone.utc
POLICIES = load_sla_policies(__import__("pathlib").Path("config/sla-policies.json"))


def test_sla_boundary_is_within():
    first = datetime(2026, 1, 1, tzinfo=UTC)
    result = apply_sla("Critical", True, first, datetime(2026, 1, 5, tzinfo=UTC), first, POLICIES)
    assert result["SlaStatus"] == "FixedWithinSla"
    assert result["SlaPolicyName"] == "CriticalKnownExploit"


def test_sla_after_boundary_is_outside():
    first = datetime(2026, 1, 1, tzinfo=UTC)
    result = apply_sla("Critical", True, first, datetime(2026, 1, 5, 0, 0, 1, tzinfo=UTC), first, POLICIES)
    assert result["SlaStatus"] == "FixedOutsideSla"


def test_generic_critical_policy_applies_without_known_exploit():
    first = datetime(2026, 1, 1, tzinfo=UTC)
    result = apply_sla("Critical", False, first, datetime(2026, 1, 3, tzinfo=UTC), first, POLICIES)
    assert result["SlaStatus"] == "FixedWithinSla"
    assert result["SlaPolicyName"] == "Critical"


def test_missing_first_seen_is_unknown():
    result = apply_sla("High", False, None, None, datetime(2026, 1, 1, tzinfo=UTC), POLICIES)
    assert result["SlaStatus"] == "Unknown"


def test_policy_config_is_versioned_and_returns_sla_start():
    config = load_sla_policy_config(__import__("pathlib").Path("config/sla-policies.json"))
    first = datetime(2026, 1, 1, tzinfo=UTC)

    result = apply_sla("High", False, first, None, first, config["policies"], config["policyVersion"])

    assert config["schemaVersion"] == 1
    assert "complianceTargetPercent" in config
    assert config["lifecycle"]["fixedConfirmationRuns"] == 2
    assert result["SlaPolicyVersion"] == config["policyVersion"]
    assert result["SlaStartUtc"] == "2026-01-01T00:00:00Z"


@pytest.mark.parametrize("target", [0, -1, 100.1, True, "90"])
def test_policy_config_rejects_invalid_compliance_target(tmp_path: Path, target):
    policy_path = tmp_path / "sla-policies.json"
    policy_path.write_text(json.dumps({"complianceTargetPercent": target, "policies": []}))

    with pytest.raises(ValueError, match="complianceTargetPercent"):
        load_sla_policy_config(policy_path)


@pytest.mark.parametrize("target", [75, 90.5, 100, None])
def test_policy_config_accepts_optional_compliance_target(tmp_path: Path, target):
    policy_path = tmp_path / "sla-policies.json"
    policy_path.write_text(json.dumps({"complianceTargetPercent": target, "policies": []}))

    assert load_sla_policy_config(policy_path)["complianceTargetPercent"] == target