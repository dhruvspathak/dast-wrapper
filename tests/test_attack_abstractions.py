import asyncio

from app.attack_engine.attacks import BOLAAttack, WorkflowTransitionAttack
from app.models.authorization import ObjectReference, Session, TrafficLog
from app.validation.engine import ValidationEngine


class DummyClient:
    pass


def traffic_log(**overrides) -> TrafficLog:
    values = {
        "id": "traffic-a",
        "workspace_id": "default",
        "application_id": "app",
        "scan_job_id": "scan",
        "identity_id": "alice",
        "request_url": "http://app.test/api/orders/101",
        "request_method": "GET",
        "request_headers": {},
        "response_status": 200,
        "response_headers": {},
        "response_body": '{"order_id":101,"status":"created"}',
        "source": "crawler",
    }
    values.update(overrides)
    return TrafficLog(**values)


def test_bola_attack_discovers_cross_identity_object_targets() -> None:
    async def run() -> None:
        attack = BOLAAttack(None, ValidationEngine(), DummyClient())
        sessions = {
            "alice": Session(id="session-a", identity_id="alice", application_id="app", workspace_id="default", status="active"),
            "bob": Session(id="session-b", identity_id="bob", application_id="app", workspace_id="default", status="active"),
        }
        refs = [
            ObjectReference(
                id="ref",
                workspace_id="default",
                application_id="app",
                identity_id="alice",
                reference_type="numeric_id",
                value="101",
                location="path",
            )
        ]

        targets = await attack.discover_targets(traffic=[traffic_log()], sessions=sessions, references=refs)

        assert len(targets) == 1
        assert targets[0].target_session.identity_id == "bob"

    asyncio.run(run())


def test_workflow_attack_detects_status_transition_surface() -> None:
    async def run() -> None:
        attack = WorkflowTransitionAttack(None, ValidationEngine(), DummyClient())
        sessions = {
            "alice": Session(id="session-a", identity_id="alice", application_id="app", workspace_id="default", status="active"),
            "bob": Session(id="session-b", identity_id="bob", application_id="app", workspace_id="default", status="active"),
        }

        targets = await attack.discover_targets(
            traffic=[traffic_log(request_method="POST", request_body='{"status":"approved"}')],
            sessions=sessions,
            references=[],
        )

        assert len(targets) == 1
        assert targets[0].mutation == {"reason": "workflow_state_token_detected"}

    asyncio.run(run())
