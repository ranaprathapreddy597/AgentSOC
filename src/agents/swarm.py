import logging
from typing import Dict, Any
from .triage import TriageAgent
from .forensics import GraphForensicsAgent
from .remediation import RemediationAgent

logger = logging.getLogger(__name__)

class SOCSwarmOrchestrator:
    """
    Autonomous Asynchronous Multi-Agent SOC Swarm Orchestrator.
    Coordinates TriageAgent, GraphForensicsAgent, and RemediationAgent
    to evaluate telemetry incidents in sub-500ms SLA.
    """

    def __init__(self):
        self.triage_agent = TriageAgent()
        self.forensics_agent = GraphForensicsAgent()
        self.remediation_agent = RemediationAgent()

    async def process_incident(self, enriched_incident: Dict[str, Any], guardrail_status: str) -> Dict[str, Any]:
        """
        Executes the multi-agent swarm workflow asynchronously.
        """
        # Step 1: Triage Evaluation
        triage_report = await self.triage_agent.analyze(enriched_incident, guardrail_status)

        # Step 2: Graph Forensics Investigation
        forensics_report = await self.forensics_agent.investigate(enriched_incident, triage_report)

        # Step 3: Remediation & Sovereign Compliance
        remediation_result = await self.remediation_agent.execute_playbook(
            enriched_incident,
            forensics_report,
            triage_report
        )

        return {
            "incident_hypothesis": remediation_result["hypothesis"],
            "simulation_valid": forensics_report["simulation_valid"],
            "composite_risk_score": remediation_result["composite_risk_score"],
            "playbook_workflow": remediation_result["playbook_workflow"],
            "audit_log_ref": remediation_result["audit_log_ref"],
            "triage_report": triage_report,
            "forensics_report": forensics_report
        }
