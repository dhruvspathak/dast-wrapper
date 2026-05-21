from app.validation.engine import ValidationEngine


def test_validation_confirms_cross_identity_sensitive_access() -> None:
    result = ValidationEngine().validate(
        baseline_response={"status_code": 200, "body": '{"id":101,"email":"a@example.com","status":"approved"}'},
        replay_response={"status_code": 200, "body": '{"id":102,"email":"b@example.com","status":"approved"}'},
        attack_type="BOLA",
    )

    assert result["verdict"] == "confirmed"
    assert result["confidence"] >= 0.75
    assert "email" in result["sensitive_fields"]
    assert "normalized_diff" in result
    assert result["validation_reasons"]


def test_validation_marks_denied_replay_as_blocked() -> None:
    result = ValidationEngine().validate(
        baseline_response={"status_code": 200, "body": '{"id":101}'},
        replay_response={"status_code": 403, "body": '{"error":"forbidden"}'},
        attack_type="horizontal_privilege_escalation",
    )

    assert result["verdict"] == "blocked"
    assert "replay_identity_was_denied" in result["validation_reasons"]
