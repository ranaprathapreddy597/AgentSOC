import hashlib
import json
import time
import logging
from typing import Dict, Any
logger = logging.getLogger(__name__)

class AdaptivePlaybook:
    """
    Adaptive Playbook Generator.
    Dynamically maps incident hypothesis & composite risk scores to automated containment workflows.
    """

    def generate_workflow(self, hypothesis: Any, risk_score: float) -> Dict[str, Any]:
        """
        Generates automated remediation steps based on risk threshold.
        Threshold > 0.6 triggers high-impact containment; <= 0.6 triggers monitoring/rotation.
        """
        if risk_score > 0.6:
            primary_action = "Isolate Host"
            steps = [
                "1. Isolate Host from internal subnet via EDR API",
                "2. Block IP Infrastructure on edge perimeter firewalls",
                "3. Revoke Active Sessions and invalidate IAM tokens"
            ]
            severity = "CRITICAL"
        else:
            primary_action = "Monitor"
            steps = [
                "1. Increase logging verbosity on source asset",
                "2. Rotate API Token and flag session for audit",
                "3. Continue real-time telemetry observation"
            ]
            severity = "LOW_MEDIUM"

        return {
            "primary_action": primary_action,
            "severity": severity,
            "risk_score_evaluated": risk_score,
            "mitre_tactics": hypothesis.mitre_tactics,
            "execution_steps": steps
        }


class SovereignAuditLogger:
    """
    Sovereign Audit Logger.
    Simulates writing to an AWS S3 Object Lock (WORM) bucket to meet 180-day immutable retention mandate.
    """

    def __init__(self, bucket_name: str = "agentsoc-sovereign-worm-vault"):
        self.bucket_name = bucket_name
        self.retention_days = 180
        self.lock_mode = "COMPLIANCE"

    def log_incident(self, incident_data: Dict[str, Any]) -> str:
        """
        Permanently logs enriched, PII-redacted incident payload to WORM storage with 180-day retention lock.
        Returns immutable audit log reference ID.
        """
        timestamp = time.time()
        record_payload = {
            "timestamp": timestamp,
            "bucket": self.bucket_name,
            "object_lock_mode": self.lock_mode,
            "retention_days": self.retention_days,
            "data": incident_data
        }

        # Generate deterministic SHA256 audit reference ID
        serialized = json.dumps(record_payload, sort_keys=True, default=str)
        hash_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:20]
        audit_log_ref = f"WORM-S3-{hash_digest.upper()}"

        logger.info(f"Incident log written to WORM storage bucket '{self.bucket_name}' | Ref: {audit_log_ref}")
        return audit_log_ref
