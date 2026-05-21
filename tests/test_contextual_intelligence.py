from app.intelligence.adaptive_planner import AdaptiveAttackPlanner
from app.intelligence.application_mapper import ApplicationMap, ApplicationMapper
from app.intelligence.expectations import ExpectedAccess
from app.intelligence.relationships import ObjectRelationshipGraph
from app.intelligence.strategy import ScanStrategyPlanner
from app.models.authorization import Endpoint


def test_application_mapper_clusters_workflow_endpoints() -> None:
    mapper = ApplicationMapper(db=None)
    endpoints = [
        Endpoint(id="e1", workspace_id="default", application_id="app", method="GET", url="/orders/1", path="/orders/1", normalized_path="/orders/{int}"),
        Endpoint(id="e2", workspace_id="default", application_id="app", method="POST", url="/orders/1/approve", path="/orders/1/approve", normalized_path="/orders/{int}/approve"),
        Endpoint(id="e3", workspace_id="default", application_id="app", method="POST", url="/orders/1/refund", path="/orders/1/refund", normalized_path="/orders/{int}/refund"),
    ]

    clusters = mapper._cluster_endpoints(endpoints)
    workflows = mapper._infer_workflows(clusters, [])

    assert "orders" in clusters
    assert {"approve", "refund"} <= {item["crud"] for item in workflows["orders"]}


def test_adaptive_planner_prioritizes_denied_privileged_expectation() -> None:
    app_map = ApplicationMap(
        workflows={"orders": [{"crud": "approve"}, {"crud": "create"}]},
        entities={"orders": {"actions": ["create", "approve"]}},
    )
    expectations = [
        ExpectedAccess("role", "buyer", "workflow", "orders", "deny", 0.82, ["buyer_should_not_approve"])
    ]

    plan = AdaptiveAttackPlanner().plan(app_map=app_map, expectations=expectations)

    assert plan.prioritized()[0].attack_type == "vertical_privilege_escalation"
    assert any(step.action == "chain_create_to_approve" for step in plan.steps)


def test_relationship_graph_builds_ownership_chains() -> None:
    graph = ObjectRelationshipGraph(
        edges=[
            {"source": "invoice", "target": "account", "relationship_type": "belongs_to"},
            {"source": "account", "target": "tenant", "relationship_type": "belongs_to"},
        ]
    )

    assert ["invoice", "account", "tenant"] in graph.ownership_chains()


def test_strategy_planner_avoids_low_value_noise() -> None:
    app_map = ApplicationMap(entities={"orders": {"actions": ["read", "approve"]}})
    plan = AdaptiveAttackPlanner().plan(
        app_map=app_map,
        expectations=[ExpectedAccess("role", "buyer", "workflow", "orders", "deny", 0.9, ["privileged"])],
    )

    strategy = ScanStrategyPlanner().plan(app_map, plan)

    assert strategy["high_risk_entities"] == ["orders"]
    assert strategy["noise_controls"]["dedupe_by_normalized_hash"] is True
