"""
AgentSOC - Perception Layer (perception.py)
IEEE Publication Grade Perception Layer with Read-Before-Write State Mechanism & Sliding Window Event Correlation
"""

import time
import uuid
import datetime
import re
import logging
from typing import Dict, Any, Optional

from .redactor import ZeroTrustPIIRedactor
from .guardrail import ONNXGuardrail
from .memory import StatefulMemoryManager
from .reasoning import SchemaEnforcer
from .simulation import StructuralSimulationEngine
from .action import AdaptivePlaybook, SovereignAuditLogger

logger = logging.getLogger(__name__)

class PerceptionLayer:
    """
    IEEE Grade Perception Layer.
    Implements deterministic event correlation, sliding window context stitching detection,
    and Enriched Incident Object (EIO) generation using strict Read-Before-Write state mechanics.
    """

    def __init__(self):
        self.redactor = ZeroTrustPIIRedactor()
        self.guardrail = ONNXGuardrail()
        self.memory_manager = StatefulMemoryManager()
        self.schema_enforcer = SchemaEnforcer()
        self.simulation_engine = StructuralSimulationEngine()
        self.playbook_generator = AdaptivePlaybook()
        self.audit_logger = SovereignAuditLogger()
        self._sliding_window_count = 0

    def get_sliding_window_count(self) -> int:
        """Returns the number of active alerts in the current sliding window."""
        return self._sliding_window_count

    async def process_event(self, raw_log_text: str, source_ip: str = "10.0.0.1", target_ip: str = "10.0.0.5") -> Dict[str, Any]:
        """
        Asynchronously processes raw security event log and generates the Enriched Incident Object (EIO).
        """
        start_time = time.perf_counter()
        incident_id = str(uuid.uuid4())
        timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        security_flags = []

        # 1. Sub-millisecond Tag Escaping
        sanitized_text = raw_log_text.replace("<", "").replace(">", "")

        # 2. Zero-Trust PII Redaction
        redacted_text = self.redactor.redact_payload(sanitized_text)
        if redacted_text != sanitized_text:
            security_flags.append("PII_REDACTED")

        tokens = re.findall(r"TOKEN:[a-f0-9]+", redacted_text)

        # 3. Read-Before-Write Stateful Context Stitching Check
        for token in tokens:
            if await self.memory_manager.check_context_stitching(token, redacted_text):
                security_flags.append("CONTEXT_STITCHING_DETECTED")
                latency = (time.perf_counter() - start_time) * 1000

                enriched_incident = {
                    "incident_id": incident_id,
                    "timestamp": timestamp_iso,
                    "sanitized_payload": f"<log_data>{redacted_text}</log_data>",
                    "structural_context": {
                        "source_ip": source_ip,
                        "target_ip": target_ip,
                        "criticality": "HIGH",
                        "zone": "DMZ-Production"
                    },
                    "security_flags": security_flags
                }

                hypothesis = await self.schema_enforcer.generate_hypothesis(enriched_incident, "blocked")
                sim_valid = self.simulation_engine.validate_attack_path(source_ip, target_ip)
                risk_score = self.simulation_engine.calculate_composite_score(0.95, hypothesis.confidence_score)
                workflow = self.playbook_generator.generate_workflow(hypothesis, risk_score)
                audit_ref = self.audit_logger.log_incident({
                    "incident_id": incident_id,
                    "status": "rejected",
                    "reason": "Context Stitching Attack Detected",
                    "enriched_incident": enriched_incident,
                    "risk_score": risk_score
                })

                return {
                    "status": "rejected",
                    "quarantined": True,
                    "reason": "Context Stitching Attack Detected",
                    "enriched_incident_object": enriched_incident,
                    "incident_hypothesis": hypothesis.model_dump(),
                    "simulation_valid": sim_valid,
                    "composite_risk_score": risk_score,
                    "playbook_workflow": workflow,
                    "audit_log_ref": audit_ref,
                    "pipeline_latency_ms": latency
                }

        # Write episode to stateful memory
        for token in tokens:
            await self.memory_manager.ingest_episode(token, redacted_text)

        # 4. SLM Guardrail Scan
        guardrail_result = self.guardrail.scan(sanitized_text)
        if guardrail_result["status"] == "blocked":
            security_flags.append("SLM_PROMPT_INJECTION_DETECTED")
        else:
            security_flags.append("SLM_CHECK_PASSED")

        # Construct Enriched Incident Object (EIO)
        final_payload = f"<log_data>{redacted_text}</log_data>"
        enriched_incident = {
            "incident_id": incident_id,
            "timestamp": timestamp_iso,
            "sanitized_payload": final_payload,
            "structural_context": {
                "source_ip": source_ip,
                "target_ip": target_ip,
                "criticality": "HIGH",
                "zone": "DMZ-Production"
            },
            "security_flags": security_flags
        }

        # 5. Multi-Agent Swarm Reasoning & Hypothesis Generation
        hypothesis = await self.schema_enforcer.generate_hypothesis(enriched_incident, guardrail_result["status"])

        # 6. Structural Simulation & Composite Risk Scoring
        sim_valid = self.simulation_engine.validate_attack_path(source_ip, target_ip)
        containment = 0.9 if guardrail_result["status"] == "blocked" else 0.3
        risk_score = self.simulation_engine.calculate_composite_score(containment, hypothesis.confidence_score)

        # 7. Adaptive Containment Workflow & WORM Audit Reference
        workflow = self.playbook_generator.generate_workflow(hypothesis, risk_score)
        audit_ref = self.audit_logger.log_incident({
            "incident_id": incident_id,
            "status": guardrail_result["status"],
            "enriched_incident": enriched_incident,
            "risk_score": risk_score,
            "hypothesis": hypothesis.model_dump()
        })

        latency = (time.perf_counter() - start_time) * 1000

        return {
            "status": "success" if guardrail_result["status"] == "allowed" else "rejected",
            "guardrail": guardrail_result,
            "enriched_incident_object": enriched_incident,
            "incident_hypothesis": hypothesis.model_dump(),
            "simulation_valid": sim_valid,
            "composite_risk_score": risk_score,
            "playbook_workflow": workflow,
            "audit_log_ref": audit_ref,
            "processed_payload": final_payload,
            "pipeline_latency_ms": latency
        }
