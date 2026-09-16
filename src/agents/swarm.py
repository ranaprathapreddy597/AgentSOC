import logging
import asyncio
import json
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class RedAgent:
    """Analyzes the EIO and proposes the most likely attacker progression."""
    async def analyze(self, eio: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Red Agent generating attacker progression hypothesis.")
        await asyncio.sleep(0.001)
        # Mocking LLM inference
        return {
            "hypothesis": "Lateral movement via SMB exploit",
            "tactics": ["TA0008"],
            "techniques": ["T1021.002"],
            "severity": "HIGH"
        }

class BlueAgent:
    """Argues the structural defenses and proposes MITRE mitigations."""
    async def analyze(self, eio: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Blue Agent generating defense and mitigation hypothesis.")
        await asyncio.sleep(0.001)
        return {
            "hypothesis": "Lateral movement via SMB exploit",
            "mitigations": ["Isolate host", "Disable SMBv1"],
            "tactics": ["TA0008"],
            "techniques": ["T1021.002"]
        }

class JudgeAgent:
    """Acts as the synthesizer, taking Red/Blue debate and querying DualRAGConnectionManager."""
    def __init__(self, dual_rag_manager: Any = None):
        self.dual_rag_manager = dual_rag_manager

    async def synthesize(self, red_output: Dict[str, Any], blue_output: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Judge Agent synthesizing Red and Blue assessments.")
        await asyncio.sleep(0.002)
        return {
            "suspected_tactic": "Lateral Movement",
            "technique_id": "T1021.002",
            "counterfactual_hypotheses": [
                "The attacker may attempt to dump credentials next.",
                "Ransomware deployment payload staging."
            ],
            "mitigations_proposed": blue_output.get("mitigations", []),
            "judge_rationale": "Synthesized from divergent Red/Blue analysis."
        }

class MultiAgentEpistemicDebate:
    """
    Multi-Agent Epistemic Debate (MAED) Engine.
    Replaces the single-shot NCE with a lightweight state machine to mathematically 
    reduce LLM hallucination variance.
    """
    def __init__(self, dual_rag_manager: Any = None):
        self.red_agent = RedAgent()
        self.blue_agent = BlueAgent()
        self.judge_agent = JudgeAgent(dual_rag_manager)

    def _calculate_similarity(self, dict1: Dict[str, Any], dict2: Dict[str, Any]) -> float:
        """
        Calculates a mathematical similarity score between Red and Blue outputs.
        """
        # Simplified similarity calculation based on matching keys/values
        matches = 0
        total = 0
        for key in ["hypothesis", "tactics", "techniques"]:
            val1 = str(dict1.get(key, ""))
            val2 = str(dict2.get(key, ""))
            if val1 and val2:
                total += 1
                if val1 == val2:
                    matches += 1
        return (matches / total) if total > 0 else 0.0

    async def generate_hypotheses(self, sanitized_eio: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the MAED state machine.
        """
        logger.info("[MAED] Initiating Multi-Agent Epistemic Debate.")
        
        # Concurrent execution of Red and Blue personas
        red_future = self.red_agent.analyze(sanitized_eio)
        blue_future = self.blue_agent.analyze(sanitized_eio)
        
        red_output, blue_output = await asyncio.gather(red_future, blue_future)
        
        # Early-stopping constraint: bypass Judge if similarity > 90%
        similarity = self._calculate_similarity(red_output, blue_output)
        logger.debug(f"[MAED] Red/Blue assessment similarity: {similarity * 100:.2f}%")
        
        if similarity > 0.90:
            logger.info("[MAED] Early-stopping engaged: Red and Blue achieved >90% consensus. Bypassing Judge.")
            hypothesis = {
                "suspected_tactic": "Consensus Tactics Derived",
                "technique_id": red_output.get("techniques", ["T0000"])[0],
                "counterfactual_hypotheses": [
                    red_output.get("hypothesis", "Unknown attacker progression.")
                ],
                "maed_consensus_score": similarity
            }
        else:
            logger.info("[MAED] Consensus below 90%. Invoking Judge Agent for synthesis.")
            hypothesis = await self.judge_agent.synthesize(red_output, blue_output)
            hypothesis["maed_consensus_score"] = similarity

        sanitized_eio["incident_hypothesis"] = hypothesis
        return sanitized_eio

# Keep legacy orchestrator if needed by other components, though MAED is the primary focus.
from .triage import TriageAgent
from .forensics import GraphForensicsAgent
from .remediation import RemediationAgent

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
        triage_report = await self.triage_agent.analyze(enriched_incident, guardrail_status)
        forensics_report = await self.forensics_agent.investigate(enriched_incident, triage_report)
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
