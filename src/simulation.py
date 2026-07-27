import logging
from typing import Dict, Any
from .graph_db import GraphDBManager

logger = logging.getLogger(__name__)

class StructuralSimulationEngine:
    """
    Structural Simulation Engine (SSE) & Risk Scoring Evaluation Module (RSEM).
    Validates attack hypotheses against a real embedded Cypher graph database (Kùzu DB)
    to mathematically reject hallucinated attack vectors in < 10ms.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.graph_manager = GraphDBManager(db_path=db_path)

    def validate_attack_path(self, source_ip: str, target_ip: str, tactic: str = "") -> bool:
        """
        Executes a real Cypher query to determine if a valid physical/logical network path exists between
        source_ip and target_ip in the enterprise topology graph.
        Returns False if the attack path is topologically impossible (hallucination rejection).
        """
        return self.graph_manager.has_lateral_movement_path(source_ip, target_ip)

    def calculate_composite_score(self, containment_efficacy: float, business_impact: float) -> float:
        """
        Calculates composite risk score based on formula:
        Score = (0.7 * containment_efficacy) - (0.3 * business_impact)
        Clamped to range [0.0, 1.0].
        """
        score = (0.7 * containment_efficacy) - (0.3 * business_impact)
        return round(max(0.0, min(1.0, score)), 4)
