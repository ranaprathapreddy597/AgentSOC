"""
AgentSOC - Narrative Counterfactual Engine (nce_agent.py)
IEEE Publication Grade Hypothesis Generation Layer.
Utilizes localized LLM inference (e.g., LM Studio, Ollama) to predict adversarial 
lateral movement and synthesize MITRE ATT&CK-aligned counterfactual hypotheses.
"""

import json
import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from openai import AsyncOpenAI
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


class NarrativeCounterfactualEngine:
    """
    Narrative Counterfactual Engine (NCE).
    Acts as an expert SOC Threat Hunter, analyzing the sanitized Enriched Incident Object (EIO).
    Generates strict JSON payloads mapping observations to MITRE ATT&CK tactics, techniques, 
    and counterfactual adversarial progressions.
    """

    def __init__(self, 
                 base_url: str = "http://localhost:1234/v1", 
                 api_key: str = "lm-studio",
                 model_name: str = "local-model",
                 timeout_seconds: float = 120.0):
        self.base_url = base_url
        self.api_key = api_key
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds

        self.client = None
        if HAS_OPENAI:
            # Initialize async OpenAI client configured for local inference servers
            # (e.g., LM Studio at http://localhost:1234/v1 or Ollama at http://localhost:11434/v1)
            self.client = AsyncOpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout_seconds
            )
            logger.info(f"[NCE] Initialized Local LLM Client (Target: {self.base_url})")
        else:
            logger.warning("[NCE] openai package not installed. Running in offline/fallback mode.")

        # System Prompt Engineering for strict JSON extraction and MITRE mapping
        self.system_prompt = """
You are an expert Autonomous SOC Threat Hunter in a Zero-Trust enterprise environment.
Your task is to analyze the provided Enriched Incident Object (EIO) and predict the adversary's next likely actions (Counterfactual Hypotheses).

You must respond ONLY with a valid JSON object matching this exact schema, with no markdown formatting, backticks, or extra text:
{
  "suspected_tactic": "The overarching MITRE Tactic (e.g., Lateral Movement, Defense Evasion)",
  "technique_id": "The specific MITRE Technique ID (e.g., T1021)",
  "counterfactual_hypotheses": [
    "Predict step 1 the attacker might take next",
    "Predict step 2 based on the compromised asset's network context"
  ]
}
"""

    def _get_fallback_hypothesis(self, reason: str) -> Dict[str, Any]:
        """
        Provides a safe default hypothesis when the LLM is offline or times out.
        Maintains pipeline integrity and SLA compliance.
        """
        logger.warning(f"[NCE] Using fallback hypothesis due to: {reason}")
        return {
            "suspected_tactic": "Unknown (Analysis Offline)",
            "technique_id": "T0000",
            "counterfactual_hypotheses": [
                "Isolate the affected asset immediately.",
                "Review perimeter firewall logs for anomalous outbound connections.",
                "Verify EDR agents are functioning on adjacent hosts."
            ],
            "nce_status": f"fallback_engaged ({reason})"
        }

    async def generate_hypotheses(self, sanitized_eio: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronously invokes the localized LLM to predict adversarial progressions.
        Parses the JSON response and appends it directly to the EIO payload.
        Handles connection timeouts gracefully to preserve the ingestion SLA.
        """
        if not self.client:
            hypothesis = self._get_fallback_hypothesis("OpenAI client unavailable")
            sanitized_eio["incident_hypothesis"] = hypothesis
            return sanitized_eio

        logger.debug(f"[NCE] Generating hypotheses for EIO: {sanitized_eio.get('incident_id')}")

        try:
            # Construct the prompt payload
            user_prompt = f"Analyze the following sanitized security incident telemetry:\n{json.dumps(sanitized_eio, indent=2)}"

            # Await the local LLM inference
            response = await self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_prompt.strip()},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2, # Low temperature for deterministic, analytical outputs
                max_tokens=300
            )

            raw_output = response.choices[0].message.content.strip()

            # Attempt to strip any markdown code blocks if the LLM hallucinated them despite instructions
            if raw_output.startswith("```json"):
                raw_output = raw_output[7:]
            if raw_output.startswith("```"):
                raw_output = raw_output[3:]
            if raw_output.endswith("```"):
                raw_output = raw_output[:-3]
            
            raw_output = raw_output.strip()

            # Parse the structured response
            hypothesis = json.loads(raw_output)
            hypothesis["nce_status"] = "success"

            logger.info(f"[NCE] Successfully generated hypothesis (Tactic: {hypothesis.get('suspected_tactic')})")

        except asyncio.TimeoutError:
            hypothesis = self._get_fallback_hypothesis("LLM Inference Timeout")
        except json.JSONDecodeError as e:
            hypothesis = self._get_fallback_hypothesis(f"JSON Parse Error: {e}")
            logger.error(f"[NCE] LLM produced invalid JSON: {raw_output}")
        except Exception as e:
            hypothesis = self._get_fallback_hypothesis(f"LLM Connection Error: {e}")

        # Append the analytical payload to the EIO
        sanitized_eio["incident_hypothesis"] = hypothesis
        
        return sanitized_eio
