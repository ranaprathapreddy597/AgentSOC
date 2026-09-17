import logging
import asyncio
import json
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from openai import AsyncOpenAI
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

class RedAgent:
    """Analyzes the EIO and proposes the most likely attacker progression."""
    def __init__(self, client=None, model="local-model"):
        self.client = client
        self.model = model

    async def analyze(self, eio: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Red Agent generating attacker progression hypothesis.")
        if not self.client:
            raise RuntimeError("OpenAI client not initialized")
            
        system_prompt = """
You are a Red Team Expert analyzing a security incident telemetry payload.
Respond ONLY with a valid JSON object matching this schema:
{
  "hypothesis": "String describing the most likely attacker progression",
  "tactics": ["List of MITRE Tactics e.g. TA0008"],
  "techniques": ["List of MITRE Techniques e.g. T1021.002"],
  "severity": "CRITICAL, HIGH, MEDIUM, or LOW"
}
"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt.strip()},
                {"role": "user", "content": json.dumps(eio)}
            ],
            temperature=0.2,
            max_tokens=200
        )
        
        raw_output = response.choices[0].message.content.strip()
        if raw_output.startswith("```json"): raw_output = raw_output[7:]
        if raw_output.startswith("```"): raw_output = raw_output[3:]
        if raw_output.endswith("```"): raw_output = raw_output[:-3]
        return json.loads(raw_output.strip())

class BlueAgent:
    """Argues the structural defenses and proposes MITRE mitigations."""
    def __init__(self, client=None, model="local-model"):
        self.client = client
        self.model = model

    async def analyze(self, eio: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Blue Agent generating defense and mitigation hypothesis.")
        if not self.client:
            raise RuntimeError("OpenAI client not initialized")
            
        system_prompt = """
You are a Blue Team Expert analyzing a security incident telemetry payload.
Respond ONLY with a valid JSON object matching this schema:
{
  "hypothesis": "String describing the defensive interpretation",
  "mitigations": ["List of mitigations e.g. Isolate host"],
  "tactics": ["List of MITRE Tactics e.g. TA0008"],
  "techniques": ["List of MITRE Techniques e.g. T1021.002"]
}
"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt.strip()},
                {"role": "user", "content": json.dumps(eio)}
            ],
            temperature=0.2,
            max_tokens=200
        )
        
        raw_output = response.choices[0].message.content.strip()
        if raw_output.startswith("```json"): raw_output = raw_output[7:]
        if raw_output.startswith("```"): raw_output = raw_output[3:]
        if raw_output.endswith("```"): raw_output = raw_output[:-3]
        return json.loads(raw_output.strip())

class JudgeAgent:
    """Acts as the synthesizer, taking Red/Blue debate and querying DualRAGConnectionManager."""
    def __init__(self, dual_rag_manager: Any = None, client=None, model="local-model"):
        self.dual_rag_manager = dual_rag_manager
        self.client = client
        self.model = model

    async def synthesize(self, red_output: Dict[str, Any], blue_output: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[MAED] Judge Agent synthesizing Red and Blue assessments.")
        if not self.client:
            raise RuntimeError("OpenAI client not initialized")
            
        system_prompt = """
You are the Lead Judge synthesizing Red and Blue team outputs.
Respond ONLY with a valid JSON object matching this schema:
{
  "suspected_tactic": "Synthesized MITRE Tactic",
  "technique_id": "Synthesized MITRE Technique ID",
  "counterfactual_hypotheses": ["List of hypotheses"],
  "mitigations_proposed": ["List of mitigations"],
  "judge_rationale": "Short rationale for the synthesis"
}
"""
        payload = {"red_team": red_output, "blue_team": blue_output}
        
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt.strip()},
                {"role": "user", "content": json.dumps(payload)}
            ],
            temperature=0.2,
            max_tokens=200
        )
        
        raw_output = response.choices[0].message.content.strip()
        if raw_output.startswith("```json"): raw_output = raw_output[7:]
        if raw_output.startswith("```"): raw_output = raw_output[3:]
        if raw_output.endswith("```"): raw_output = raw_output[:-3]
        return json.loads(raw_output.strip())

class MultiAgentEpistemicDebate:
    """
    Multi-Agent Epistemic Debate (MAED) Engine.
    Replaces the single-shot NCE with a lightweight state machine to mathematically 
    reduce LLM hallucination variance.
    """
    def __init__(self, dual_rag_manager: Any = None,
                 base_url: str = "http://127.0.0.1:1234/v1",
                 api_key: str = "lm-studio",
                 model_name: str = "local-model",
                 timeout_seconds: float = 120.0):
        
        self.client = None
        if HAS_OPENAI:
            self.client = AsyncOpenAI(
                base_url=base_url,
                api_key=api_key,
                timeout=timeout_seconds
            )
            
        self.red_agent = RedAgent(client=self.client, model=model_name)
        self.blue_agent = BlueAgent(client=self.client, model=model_name)
        self.judge_agent = JudgeAgent(dual_rag_manager=dual_rag_manager, client=self.client, model=model_name)

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
        import httpx
        
        try:
            # Explicit Endpoint Routing: Ping LM Studio
            async with httpx.AsyncClient(timeout=2.0) as client:
                # We attempt a minimal payload to see if the LLM is responding
                await client.get("http://127.0.0.1:1234/v1/models")
        except (httpx.ConnectError, httpx.TimeoutException):
            logger.error("[MAED] Connection refused to LM Studio on port 1234. Eliminating silent fallback.")
            sanitized_eio["incident_hypothesis"] = {
                "llm_status": "offline",
                "error": "Connection refused to LM Studio on port 1234",
                "composite_risk_score": 0.0
            }
            sanitized_eio["llm_offline_abort"] = True
            return sanitized_eio
        
        try:
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
            
        except Exception as e:
            logger.error(f"LLM Generation Failed: {str(e)}")
            sanitized_eio["incident_hypothesis"] = {
                "llm_status": "offline",
                "error": f"LLM Generation Failed: {str(e)}",
                "composite_risk_score": 0.0,
                "suspected_tactic": "LLM_ERROR",
                "technique_id": "LLM_ERROR"
            }
            sanitized_eio["llm_offline_abort"] = True
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
