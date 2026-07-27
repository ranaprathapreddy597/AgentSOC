import logging
import asyncio
from typing import Dict, Any, List, Optional
from ..simulation import StructuralSimulationEngine
from ..vector_db import VectorDBManager

logger = logging.getLogger(__name__)

class GraphForensicsAgent:
    """
    Autonomous GraphRAG Forensics Agent.
    Executes Dual-Retrieval Threat Intelligence:
    1. Structural Cypher Graph Query (Kùzu DB) for lateral topology reachability.
    2. Semantic Vector Search (Qdrant DB) for historical MITRE ATT&CK mitigation reports.
    """

    def __init__(
        self,
        simulation_engine: Optional[StructuralSimulationEngine] = None,
        vector_manager: Optional[VectorDBManager] = None
    ):
        self.simulation_engine = simulation_engine or StructuralSimulationEngine()
        self.vector_manager = vector_manager or VectorDBManager()

    async def investigate(self, enriched_incident: Dict[str, Any], triage_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronously executes Dual-Retrieval (Structural Cypher Path + Semantic Qdrant Vector Match).
        """
        source_ip = triage_report.get("source_ip", "127.0.0.1")
        target_ip = triage_report.get("target_ip", "10.0.0.5")
        sanitized_payload = enriched_incident.get("sanitized_payload", "")

        # Path 1: Structural Cypher Path Check (Kùzu DB)
        path_valid = self.simulation_engine.validate_attack_path(source_ip, target_ip)

        # Path 2: Semantic Vector Threat Intelligence Search (Qdrant DB)
        semantic_mitigations = self.vector_manager.search_similar_mitigations(
            query_text=f"{triage_report.get('attack_category', '')} {sanitized_payload}",
            top_k=3
        )

        tactics: List[str] = []
        category = triage_report.get("attack_category", "")

        if "Injection" in category or "Adversarial" in category:
            tactics = ["TA0001: Initial Access", "TA0002: Execution"]
        elif "Privileged" in category:
            tactics = ["TA0006: Credential Access"]

        forensics_report = {
            "simulation_valid": path_valid,
            "mitre_tactics": tactics,
            "semantic_mitigations": semantic_mitigations,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "confidence_score": 0.95 if triage_report.get("is_malicious") else 0.05
        }

        logger.info(
            f"[GraphForensicsAgent] Dual-Retrieval Complete | Path Valid: {path_valid} | "
            f"Retrieved {len(semantic_mitigations)} Vector Threat Intelligence Mitigations"
        )
        return forensics_report
