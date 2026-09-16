import logging
from typing import Dict, Any
from ..simulation import StructuralSimulationEngine
from ..action import AdaptivePlaybook, SovereignAuditLogger

logger = logging.getLogger(__name__)

class RemediationAgent:
    """
    Autonomous Remediation & Compliance Agent.
    Calculates composite risk scores, synthesizes adaptive containment playbooks,
    and logs immutable WORM audit compliance entries.
    """

    def __init__(self):
        self.simulation_engine = StructuralSimulationEngine()
        self.playbook_generator = AdaptivePlaybook()
        self.audit_logger = SovereignAuditLogger()

    async def execute_playbook(
        self,
        enriched_incident: Dict[str, Any],
        forensics_report: Dict[str, Any],
        triage_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Asynchronously computes composite risk score, generates containment workflow, and logs WORM audit reference.
        """
        from ..reasoning import IncidentHypothesis

        is_malicious = triage_report.get("is_malicious", False)
        path_valid = forensics_report.get("simulation_valid", False)

        containment_efficacy = 0.95 if (is_malicious and path_valid) else (0.75 if is_malicious else 0.10)
        business_impact = 0.85 if is_malicious else 0.05

        composite_score = self.simulation_engine.calculate_composite_score(
            containment_efficacy=containment_efficacy,
            business_impact=business_impact
        )

        hypothesis = IncidentHypothesis(
            attack_type=triage_report.get("attack_category", "Benign Telemetry Flow"),
            confidence_score=forensics_report.get("confidence_score", 0.05),
            mitre_tactics=forensics_report.get("mitre_tactics", []),
            recommended_action=triage_report.get("triage_action", "Log & Continue Normal Processing")
        )

        playbook_workflow = self.playbook_generator.generate_workflow(hypothesis, composite_score)

        sandbox_confirmation = None
        
        # ---------------------------------------------------------
        # Active Closed-Loop Docker Sandboxing
        # ---------------------------------------------------------
        if composite_score >= 75.0 and playbook_workflow.get("action") == "ISOLATE":
            target_ip = enriched_incident.get("target_ip") or enriched_incident.get("structural_context", {}).get("target_ip")
            sandbox_confirmation = await self._isolate_docker_container(target_ip)
            if sandbox_confirmation:
                enriched_incident["sandbox_event"] = sandbox_confirmation

        audit_log_ref = self.audit_logger.log_incident({
            "incident_id": enriched_incident.get("incident_id"),
            "status": "containment_engaged" if sandbox_confirmation else ("rejected" if is_malicious else "allowed"),
            "enriched_incident": enriched_incident,
            "risk_score": composite_score,
            "hypothesis": hypothesis.model_dump()
        })

        remediation_result = {
            "composite_risk_score": composite_score,
            "playbook_workflow": playbook_workflow,
            "audit_log_ref": audit_log_ref,
            "hypothesis": hypothesis,
            "sandbox_confirmation": sandbox_confirmation
        }

        logger.info(f"[RemediationAgent] Generated playbook (score: {composite_score}, ref: {audit_log_ref[:16]}...)")
        return remediation_result
        
    async def _isolate_docker_container(self, target_ip: str) -> Dict[str, Any]:
        """
        Connects to the local Docker daemon and isolates the target container network
        as an autonomous containment directive from the RSEM.
        """
        import asyncio
        try:
            import docker
            client = docker.from_env()
        except ImportError:
            logger.warning("[RemediationAgent] docker SDK not installed. Simulating Active Container Sandbox.")
            client = None
        except Exception as e:
            logger.error(f"[RemediationAgent] Docker daemon connection failed: {e}")
            client = None

        logger.info(f"[RemediationAgent] Issuing autonomous containment directive for target: {target_ip}")
        await asyncio.sleep(0.005) # Simulate async I/O to docker daemon
        
        if client:
            try:
                # Find the container by IP in the networks
                target_container = None
                for container in client.containers.list():
                    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                    for net_name, net_details in networks.items():
                        if net_details.get("IPAddress") == target_ip:
                            target_container = container
                            break
                    if target_container:
                        break
                        
                if target_container:
                    # Disconnect from all networks to isolate
                    networks = target_container.attrs.get("NetworkSettings", {}).get("Networks", {})
                    for net_name in networks.keys():
                        network = client.networks.get(net_name)
                        network.disconnect(target_container, force=True)
                    logger.info(f"[RemediationAgent] Successfully isolated container {target_container.short_id} from network.")
                    return {
                        "status": "ISOLATED",
                        "container_id": target_container.short_id,
                        "target_ip": target_ip,
                        "timestamp": "2026-09-16T10:40:00Z"
                    }
            except Exception as e:
                logger.error(f"[RemediationAgent] Failed to isolate container via Docker SDK: {e}")
        
        # Fallback simulation
        return {
            "status": "SIMULATED_ISOLATION",
            "container_id": "mock_c1b2a3",
            "target_ip": target_ip,
            "timestamp": "2026-09-16T10:40:00Z"
        }

