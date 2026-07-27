import json
import logging
import httpx
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from .agents.swarm import SOCSwarmOrchestrator

logger = logging.getLogger(__name__)

class IncidentHypothesis(BaseModel):
    attack_type: str = Field(..., description="Categorization of the detected security event or anomaly")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactics")
    recommended_action: str = Field(..., description="Actionable response directive")

class SchemaEnforcer:
    """
    Narrative Counterfactual Engine (NCE) powered by SOCSwarmOrchestrator multi-agent swarm.
    Maintains compatibility with LM Studio local server and guarantees strict Pydantic JSON outputs.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:1234/v1"):
        self.base_url = base_url.rstrip("/")
        self._cached_model_name = None
        self._client = None
        self.swarm = SOCSwarmOrchestrator()

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=0.05)
        return self._client

    async def _get_active_model(self, client: httpx.AsyncClient) -> str:
        if self._cached_model_name:
            return self._cached_model_name
        try:
            r = await client.get(f"{self.base_url}/models")
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    self._cached_model_name = data[0]["id"]
                    return self._cached_model_name
        except Exception:
            pass
        return "local-model"

    async def generate_hypothesis(self, enriched_incident: Dict[str, Any], guardrail_status: str) -> IncidentHypothesis:
        """
        Sends request to local LM Studio server if online, otherwise delegates to autonomous Multi-Agent Swarm.
        """
        system_prompt = (
            "You are a Senior Cybersecurity AI Analyst. Analyze the provided Enriched Incident Object. "
            "You MUST respond ONLY with a valid JSON object matching the following Pydantic schema:\n"
            "{\n"
            '  "attack_type": "string",\n'
            '  "confidence_score": 0.0-1.0,\n'
            '  "mitre_tactics": ["string"],\n'
            '  "recommended_action": "string"\n'
            "}\n"
            "Do not include any introductory or concluding text, conversational filler, or markdown code blocks."
        )

        user_content = json.dumps(enriched_incident, indent=2)

        try:
            client = self._get_client()
            model_name = await self._get_active_model(client)
            payload = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Enriched Incident Object:\n{user_content}"}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.1
            }
            response = await client.post(f"{self.base_url}/chat/completions", json=payload)
            if response.status_code == 200:
                raw_json = response.json()["choices"][0]["message"]["content"]
                return IncidentHypothesis.model_validate_json(raw_json)
        except Exception as e:
            logger.debug(f"LM Studio API call notice ({e}). Delegating to SOC Swarm Orchestrator.")

        # Multi-Agent Swarm Fallback
        swarm_result = await self.swarm.process_incident(enriched_incident, guardrail_status)
        return swarm_result["incident_hypothesis"]
