import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.simulation import StructuralSimulationEngine

client = TestClient(app)

def test_feasible_attack_path_validation():
    payload = {
        "log": "Diagnostic connection request",
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.5"
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["simulation_valid"] is True
    assert "composite_risk_score" in data
    assert isinstance(data["composite_risk_score"], float)

def test_infeasible_attack_path_hallucination_rejection():
    payload = {
        "log": "Spoofed path telemetry payload",
        "source_ip": "10.0.0.1",
        "target_ip": "172.16.99.99"
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()

    # The attack path between 10.0.0.1 and 172.16.99.99 does not exist in topology graph
    assert data["simulation_valid"] is False

def test_composite_risk_score_calculation():
    engine = StructuralSimulationEngine()

    # Formula: Score = (0.7 * containment) - (0.3 * impact)
    # Test case 1: containment=0.9, impact=0.1 -> 0.7*0.9 - 0.3*0.1 = 0.63 - 0.03 = 0.60
    score1 = engine.calculate_composite_score(0.9, 0.1)
    assert score1 == 0.6

    # Test case 2: containment=0.5, impact=0.9 -> 0.7*0.5 - 0.3*0.9 = 0.35 - 0.27 = 0.08
    score2 = engine.calculate_composite_score(0.5, 0.9)
    assert score2 == 0.08

def test_simulation_latency_sla():
    payload = {
        "log": "SLA performance validation log",
        "source_ip": "192.168.1.10",
        "target_ip": "10.0.0.5"
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["pipeline_latency_ms"] < 500
