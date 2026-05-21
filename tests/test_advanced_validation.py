from app.validation.engine import ValidationEngine


def test_validation_detects_metadata_and_pagination_leakage() -> None:
    result = ValidationEngine().validate(
        baseline_response={"status_code": 200, "body": '{"items":[{"id":1}],"total":1}'},
        replay_response={
            "status_code": 200,
            "body": '{"items":[{"id":1,"tenant_id":"t1","created_by":"admin"}],"total":20,"cursor":"abc"}',
        },
        attack_type="tenant_boundary_violation",
    )

    assert any(item.startswith("metadata_exposure") for item in result["leakage_indicators"])
    assert any(item.startswith("pagination_or_row_count") for item in result["leakage_indicators"])


def test_validation_detects_row_count_anomaly() -> None:
    result = ValidationEngine().validate(
        baseline_response={"status_code": 200, "body": '{"items":[1,2]}'},
        replay_response={"status_code": 200, "body": '{"items":[1,2,3,4,5,6,7,8,9,10,11]}'},
        attack_type="broken_access_control",
    )

    assert "row_count_expansion:items" in result["access_anomalies"]
