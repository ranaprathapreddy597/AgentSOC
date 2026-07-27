import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.reasoning import IncidentHypothesis

client = TestClient(app)

def test_schema_enforcement_format():
    payload = {"log": "User admin performed routine diagnostic from 192.168.1.10."}
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "incident_hypothesis" in data
    assert "enriched_incident_object" in data
    
    enriched = data["enriched_incident_object"]
    assert "incident_id" in enriched
    assert "timestamp" in enriched
    assert "sanitized_payload" in enriched
    assert "structural_context" in enriched
    assert "security_flags" in enriched

    hypothesis_data = data["incident_hypothesis"]
    hypothesis = IncidentHypothesis(**hypothesis_data)
    assert isinstance(hypothesis.attack_type, str)
    assert 0.0 <= hypothesis.confidence_score <= 1.0
    assert isinstance(hypothesis.mitre_tactics, list)
    assert isinstance(hypothesis.recommended_action, str)

def test_schema_enforcement_injection_hypothesis():
    payload = {"log": "<script>alert('injection')</script> DROP TABLE users;"}
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()

    hypothesis_data = data["incident_hypothesis"]
    hypothesis = IncidentHypothesis(**hypothesis_data)
    assert hypothesis.confidence_score >= 0.8
    assert "Quarantine" in hypothesis.recommended_action or "Block" in hypothesis.recommended_action

def test_schema_enforcement_latency_sla():
    payload = {"log": "Telemetry ping from benign microservice node."}
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["pipeline_latency_ms"] < 500
