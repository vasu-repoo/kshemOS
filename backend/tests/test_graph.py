
import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app

TOKEN = "test-graph-analyst-token-that-is-long-enough-123456"

client = TestClient(
    app,
    headers={"Authorization": f"Bearer {TOKEN}"},
)


@pytest.fixture(autouse=True)
def configure_graph_auth(monkeypatch):
    monkeypatch.setenv(
        "FRAUD_GRAPH_ANALYST_TOKENS",
        json.dumps({TOKEN: "ANALYST-001"}),
    )


def test_graph_edges_include_explainability_metadata():
    response = client.get("/api/graph/ring/ACC-1001")

    assert response.status_code == 200

    data = response.json()

    # Preserve the existing API response contract.
    assert data["account_id"] == "ACC-1001"
    assert data["connected_accounts"] == ["ACC-1002"]
    assert data["shared_signals"] == ["SHARED_DEVICE"]

    # Every relationship must have its own explanation.
    assert "edges" in data
    assert len(data["edges"]) == 1

    edge = data["edges"][0]

    required_fields = {
        "edge_id",
        "source",
        "target",
        "relationship_type",
        "source_signal",
        "observed_at",
        "confidence",
        "provenance",
    }

    assert required_fields.issubset(edge.keys())

    assert edge["source"] == "ACC-1001"
    assert edge["target"] == "ACC-1002"
    assert edge["relationship_type"] == "SHARED_DEVICE"

    assert isinstance(edge["source_signal"], str)
    assert edge["source_signal"].strip()

    datetime.fromisoformat(
        edge["observed_at"].replace("Z", "+00:00")
    )

    assert isinstance(edge["confidence"], (int, float))
    assert 0 <= edge["confidence"] <= 1

    assert edge["provenance"] == "synthetic"


def test_graph_returns_explainable_paths():
    response = client.get("/api/graph/ring/ACC-1001")

    assert response.status_code == 200

    data = response.json()

    assert "paths" in data

    # ACC-1001 -> ACC-1002 -> ACC-1003
    expected_path = [
        "ACC-1001",
        "ACC-1002",
        "ACC-1003",
    ]

    matching_path = next(
        (
            path for path in data["paths"]
            if path["accounts"] == expected_path
        ),
        None,
    )

    assert matching_path is not None
    assert len(matching_path["edge_ids"]) == 2
    assert len(matching_path["edge_explanations"]) == 2

    for path in data["paths"]:
        assert (
            len(path["edge_ids"])
            == len(path["edge_explanations"])
            == len(path["accounts"]) - 1
        )

        for edge_id, explanation in zip(
            path["edge_ids"],
            path["edge_explanations"],
        ):
            assert explanation["edge_id"] == edge_id
            assert explanation["source_signal"]
            assert explanation["observed_at"]
            assert 0 <= explanation["confidence"] <= 1
            assert explanation["provenance"] in {
                "verified", "inferred", "synthetic"
            }


def test_unknown_account_returns_empty_graph_explanations():
    response = client.get("/api/graph/ring/UNKNOWN-ACCOUNT")

    assert response.status_code == 200

    data = response.json()

    assert data["edges"] == []
    assert data["paths"] == []
    assert data["connected_accounts"] == []
