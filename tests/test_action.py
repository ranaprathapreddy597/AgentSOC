import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.action import AdaptivePlaybook, SovereignAuditLogger
from src.reasoning import IncidentHypothesis

client = TestClient(app)

def test_high_risk_playbook_generation():
    playbook = AdaptivePlaybook()
    hypothesis = IncidentHypothesis(
        attack_type="Prompt Injection",
        confidence_score=0.95,
        mitre_tactics=["TA0001: Initial Access"],
        recommended_action="Quarantine"
    )
    workflow = playbook.generate_workflow(hypothesis, risk_score=0.8)

    assert workflow["primary_action"] == "Isolate Host"
    assert workflow["severity"] == "CRITICAL"
    assert len(workflow["execution_steps"]) > 0

def test_low_risk_playbook_generation():
    playbook = AdaptivePlaybook()
    hypothesis = IncidentHypothesis(
        attack_type="Benign Flow",
        confidence_score=0.05,
        mitre_tactics=[],
        recommended_action="Log & Continue"
    )
    workflow = playbook.generate_workflow(hypothesis, risk_score=0.2)

    assert workflow["primary_action"] == "Monitor"
    assert workflow["severity"] == "LOW_MEDIUM"

def test_sovereign_audit_logger_ref():
    logger = SovereignAuditLogger()
    sample_incident = {"status": "allowed", "risk_score": 0.15, "log": "test telemetry"}
    ref = logger.log_incident(sample_incident)

    assert ref.startswith("WORM-S3-")
    assert len(ref) > 10

def test_full_pipeline_action_integration():
    # Warmup /ingest pipeline endpoint stack
    client.post("/ingest", json={"log": "warmup telemetry log 127.0.0.1"})
    
    payload = {
        "log": "Unauthorized access attempt from 192.168.1.150 with DROP TABLE users;"
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "playbook_workflow" in data
    assert "audit_log_ref" in data
    assert data["audit_log_ref"].startswith("WORM-S3-")
    assert data["pipeline_latency_ms"] < 500
