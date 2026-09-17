"""
AgentSOC - Structural Simulation Engine & Risk Scoring Engine (sse_rsem.py)
IEEE Publication Grade Hypothesis Validation and Adaptive Containment Layer.
Mathematically verifies LLM hypotheses via Graph RAG, retrieves semantic mitigations via Vector RAG,
and calculates deterministic risk scores to power autonomous playbook execution.
"""

import logging
import asyncio
from typing import Dict, Any, List
from enum import Enum

from .database import DualRAGConnectionManager

logger = logging.getLogger(__name__)


class FeasibilityStatus(Enum):
    FEASIBLE = "FEASIBLE"
    CONDITIONALLY_FEASIBLE = "CONDITIONALLY_FEASIBLE"
    INFEASIBLE = "INFEASIBLE"


class StructuralSimulationEngine:
    """
    Structural Simulation Engine (SSE) & Risk Scoring Engine Model (RSEM).
    Acts as the strict mathematical boundary against LLM hallucinations. If the LLM predicts an 
    attack path that physically does not exist in the enterprise graph topology, execution is halted.
    """

    def __init__(self, db_manager: DualRAGConnectionManager = None):
        # Inject the dual-RAG manager which holds the Kùzu (Graph) and Qdrant (Vector) connections
        self.db_manager = db_manager or DualRAGConnectionManager()

    def calculate_dynamic_threshold(self, base_threshold: float, active_alerts_in_window: int) -> float:
        """
        Calculates an adaptive risk threshold based on network velocity/alert floods.
        During high-alert scenarios (e.g. active worm propagation), the threshold lowers
        to become more aggressive in containment. Hard lower bound of 0.0.
        """
        new_threshold = base_threshold - (0.1 * active_alerts_in_window)
        return max(0.0, new_threshold)

    async def calculate_adaptive_risk(self, 
                                      criticality_str: str, 
                                      llm_confidence: float, 
                                      status: FeasibilityStatus, 
                                      active_alerts_in_window: int = 0) -> Dict[str, Any]:
        """
        Asynchronous Risk Scoring Engine Model (RSEM).
        Applies mathematical probabilistic penalties for conditional feasibility.
        """
        # Map criticality strings to numerical baseline multipliers
        criticality_map = {
            "CRITICAL": 100.0,
            "HIGH": 80.0,
            "MEDIUM": 50.0,
            "LOW": 25.0
        }
        
        base_score = criticality_map.get(criticality_str.upper(), 50.0)
        
        # Calculate composite risk score
        final_risk_score = base_score * llm_confidence

        # Apply probabilistic penalty if the path is conditionally feasible
        if status == FeasibilityStatus.CONDITIONALLY_FEASIBLE:
            logger.info("[RSEM] Applying 0.6 penalty weight due to CONDITIONALLY_FEASIBLE status.")
            final_risk_score *= 0.6
            
        final_risk_score = round(final_risk_score, 2)
        
        # Calculate Dynamic Threshold
        threshold = self.calculate_dynamic_threshold(75.0, active_alerts_in_window)
        logger.info(f"[RSEM] Computed Risk Score: {final_risk_score} (Dynamic Threshold: {threshold})")

        # Threshold decision boundary
        if final_risk_score >= threshold:
            return {
                "risk_score": final_risk_score,
                "action": "ISOLATE_HOST",
                "mode": "AUTONOMOUS",
                "justification": f"Risk threshold exceeded (>={threshold}). Engaging autonomous containment."
            }
        else:
            return {
                "risk_score": final_risk_score,
                "action": "QUARANTINE_WARNING",
                "mode": "DRY_RUN",
                "justification": f"Risk below autonomous threshold (<{threshold}). Initiating dry-run telemetry."
            }

    async def evaluate_incident(self, eio: Dict[str, Any], active_alerts_in_window: int = 0) -> Dict[str, Any]:
        """
        Orchestrates the mathematical validation, mitigation Retrieval, and risk scoring.
        Takes the Enriched Incident Object (EIO) and augments it with validation context.
        """
        logger.debug(f"[SSE] Starting structural evaluation for EIO: {eio.get('incident_id')}")

        source_ip = eio.get("structural_context", {}).get("source_ip", "")
        target_ip = eio.get("structural_context", {}).get("target_ip", "")
        criticality = eio.get("structural_context", {}).get("criticality", "HIGH")
        
        hypothesis = eio.get("incident_hypothesis", {})
        
        if eio.get("llm_offline_abort"):
            logger.warning("[SSE] LLM Offline Abort flag detected. Bypassing RSEM validation.")
            eio["sse_validation"] = {
                "status": "INFEASIBLE",
                "reason": "LLM_OFFLINE",
                "containment_playbook": {
                    "risk_score": 0.0,
                    "action": "NONE",
                    "mode": "OFFLINE"
                }
            }
            return eio
        
        # We assume a default confidence if the local LLM didn't provide one
        llm_confidence = hypothesis.get("confidence", 0.90) 
        technique_id = hypothesis.get("technique_id", "T1021")

        # -------------------------------------------------------------
        # 1. Dual-RAG Synthesis (Concurrent Kùzu + Qdrant)
        # -------------------------------------------------------------
        try:
            rag_result = await self.db_manager.synthesize_rag_context(source_ip, target_ip, technique_id)
            is_path_valid = rag_result.get("path_valid", False)
            mitigations = rag_result.get("mitigations", [])
        except Exception as e:
            logger.error(f"[SSE] DualRAG Synthesis Failure: {e}")
            is_path_valid = False
            mitigations = []

        if not is_path_valid:
            status = FeasibilityStatus.INFEASIBLE
            logger.warning(f"[SSE] Network topology rejection: No path from {source_ip} to {target_ip}. LLM Hallucination detected.")
            eio["sse_validation"] = {
                "status": status.value,
                "reason": "HALLUCINATION_DETECTED",
                "details": "The LLM predicted an attack trajectory that physically does not exist in the network topology."
            }
            return eio
            
        # Check conditional feasibility (e.g. missing privileges)
        if hypothesis.get("missing_privileges", False):
            status = FeasibilityStatus.CONDITIONALLY_FEASIBLE
        else:
            status = FeasibilityStatus.FEASIBLE

        # -------------------------------------------------------------
        # 2. Risk Scoring Engine (RSEM)
        # -------------------------------------------------------------
        playbook = await self.calculate_adaptive_risk(criticality, llm_confidence, status, active_alerts_in_window)

        # Attach validated results to the EIO
        eio["sse_validation"] = {
            "status": status.value,
            "reason": "STRUCTURALLY_FEASIBLE",
            "recommended_mitigations": mitigations,
            "containment_playbook": playbook
        }

        return eio
