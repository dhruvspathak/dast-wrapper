from app.workflows.state_machine import WorkflowDiscoveryEngine, WorkflowStateMachine


def test_state_machine_flags_suspicious_transition() -> None:
    machine = WorkflowStateMachine()
    machine.add_transition("created", "approved")

    assert machine.is_suspicious("created", "approved") is True
    assert machine.as_dict() == {"created": ["approved"]}


def test_workflow_discovery_extracts_state_fields() -> None:
    engine = WorkflowDiscoveryEngine(db=None)

    states = engine._extract_states('{"invoice":{"status":"paid","approval_status":"approved"}}')

    assert states == ["paid", "approved"]
