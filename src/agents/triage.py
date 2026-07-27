import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class TriageAgent:
    """
    Autonomous Triage Agent.
    Evaluates perimeter guardrail flags, sanitization tokens, and payload characteristics
    to assign an initial threat classification and severity score.
    """

    def __init__(self):
        pass

    async def analyze(self, enriched_incident: Dict[str, Any], guardrail_status: str) -> Dict[str, Any]:
        """
        Asynchronously evaluates the Enriched Incident Object and returns a triage report.
        """
        sec_flags = enriched_incident.get("security_flags", [])
        sanitized_payload = enriched_incident.get("sanitized_payload", "").lower()
        context = enriched_incident.get("structural_context", {})

        is_injection = (
            guardrail_status == "blocked" or
            "SLM_PROMPT_INJECTION_DETECTED" in sec_flags or
            "CONTEXT_STITCHING_DETECTED" in sec_flags
        )

        has_privilege_indicators = "admin" in sanitized_payload or "drop table" in sanitized_payload or "login" in sanitized_payload

        if is_injection:
            initial_severity = "CRITICAL"
            attack_category = "Prompt Injection / Adversarial Evasion"
            triage_action = "Quarantine Payload & Block Source IP"
        elif has_privilege_indicators:
            initial_severity = "HIGH"
            attack_category = "Privileged Telemetry Anomaly"
            triage_action = "Monitor Session & Audit Privileges"
        else:
            initial_severity = "LOW_MEDIUM"
            attack_category = "Benign Telemetry Flow"
            triage_action = "Log & Continue Normal Processing"

        triage_report = {
            "initial_severity": initial_severity,
            "attack_category": attack_category,
            "triage_action": triage_action,
            "source_ip": context.get("source_ip", "127.0.0.1"),
            "target_ip": context.get("target_ip", "10.0.0.5"),
            "is_malicious": is_injection or has_privilege_indicators
        }

        logger.info(f"[TriageAgent] Categorized incident as {initial_severity} ({attack_category})")
        return triage_report
