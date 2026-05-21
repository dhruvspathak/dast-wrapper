from app.validation.normalization import ResponseNormalizer


def test_normalization_removes_dynamic_values() -> None:
    normalizer = ResponseNormalizer()
    left = '{"id":"550e8400-e29b-41d4-a716-446655440000","csrf_token":"abc","updated_at":"2026-05-22T10:11:12Z"}'
    right = '{"id":"550e8400-e29b-41d4-a716-446655440999","csrf_token":"def","updated_at":"2026-05-22T10:12:12Z"}'

    diff = normalizer.semantic_diff(left, right)

    assert diff["structure_equal"] is True
    assert diff["body_equal"] is True


def test_structural_json_diff_reports_added_fields() -> None:
    normalizer = ResponseNormalizer()

    diff = normalizer.semantic_diff('{"id":1}', '{"id":1,"email":"a@example.com"}')

    assert "email" in diff["schema_added"]
