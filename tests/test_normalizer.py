from vulnerability_view.normalizer import priority_score


def test_priority_score_is_explainable_and_bounded():
    score, explanation = priority_score({"Severity": "Critical", "CvssScore": 10, "VerifiedExploitAvailable": True, "PublicExploitAvailable": True, "InternetFacing": True, "DeviceExposureLevel": "High", "AssetCriticality": "Critical"})
    assert score == 100
    assert "Severity" in explanation and "internet" in explanation


def test_unknown_live_severity_has_no_severity_points():
    score, explanation = priority_score({"Severity": "Unknown", "CvssScore": 0, "VerifiedExploitAvailable": False, "PublicExploitAvailable": False, "InternetFacing": False, "DeviceExposureLevel": "Unknown", "AssetCriticality": "Standard"})
    assert score == 2
    assert explanation.startswith("Severity 0")
