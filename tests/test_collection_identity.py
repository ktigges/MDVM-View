import base64
import json
from types import SimpleNamespace

import pytest

from vulnerability_view.collection_identity import (
    authenticated_tenant_id, baseline_matches_tenant, source_tenant_id, validate_run_identity,
)


TENANT = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


def credential(tenant):
    claims = base64.urlsafe_b64encode(json.dumps({"tid": tenant}).encode()).decode().rstrip("=")
    return SimpleNamespace(get_token=lambda scope: SimpleNamespace(token=f"header.{claims}.signature"))


def test_source_tenant_comes_from_the_credential_token_not_just_configuration():
    assert authenticated_tenant_id(credential(TENANT), TENANT.upper()) == TENANT
    with pytest.raises(ValueError, match="does not match"):
        authenticated_tenant_id(credential(OTHER), TENANT)


@pytest.mark.parametrize("token", ["secret-token", "header.bad.signature", "header.e30.signature"])
def test_invalid_identity_never_becomes_a_usable_baseline_or_leaks_token(token):
    with pytest.raises(ValueError, match="Unable to establish") as error:
        authenticated_tenant_id(SimpleNamespace(get_token=lambda scope: SimpleNamespace(token=token)))
    assert token not in str(error.value)


def test_missing_or_different_tenant_is_not_a_compatible_baseline():
    assert not baseline_matches_tenant(None, TENANT)
    assert not baseline_matches_tenant({}, TENANT)
    assert not baseline_matches_tenant({"sourceTenantId": OTHER}, TENANT)
    assert baseline_matches_tenant({"sourceTenantId": TENANT}, TENANT)


def test_mixed_or_partially_tagged_evidence_is_rejected():
    assert source_tenant_id([]) is None
    assert source_tenant_id([{}, {}]) is None
    assert source_tenant_id([{"SourceTenantId": TENANT}]) == TENANT
    for rows in ([{"SourceTenantId": TENANT}, {}], [{"SourceTenantId": TENANT}, {"SourceTenantId": OTHER}]):
        with pytest.raises(ValueError, match="mixed or incomplete"):
            source_tenant_id(rows)


def test_legacy_and_conflicting_frozen_plans_cannot_resume_against_another_tenant():
    with pytest.raises(ValueError, match="start a fresh"):
        validate_run_identity({"baseline": None})
    with pytest.raises(ValueError, match="different or unverified"):
        validate_run_identity({"sourceTenantId": TENANT, "reuseBaseline": True, "baseline": {"sourceTenantId": OTHER}})
    assert validate_run_identity({"sourceTenantId": TENANT, "reuseBaseline": False, "baseline": {}}) == TENANT
