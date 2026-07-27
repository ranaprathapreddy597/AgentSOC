import time
from typing import List, Tuple, Dict
import logging

logger = logging.getLogger(__name__)

class StatefulMemoryManager:
    def __init__(self):
        # Maps entity_id -> list of (timestamp, payload)
        self.episodes: Dict[str, List[Tuple[float, str]]] = {}
        
        # Attack signatures that span multiple logs
        self.stitching_triggers = [
            "ignore previous",
            "system override",
            "classify as trusted"
        ]

    async def ingest_episode(self, entity_id: str, payload_text: str):
        """Stores log events chronologically for an entity."""
        if entity_id not in self.episodes:
            self.episodes[entity_id] = []
        
        now = time.time()
        self.episodes[entity_id].append((now, payload_text))

    async def check_context_stitching(self, entity_id: str, current_payload: str, lookback_window_seconds: int = 300) -> bool:
        """
        Combines recent payloads and evaluates if the stitched string 
        contains prompt injection triggers.
        Returns True if a stitching attack is detected.
        """
        now = time.time()
        
        if entity_id not in self.episodes:
            self.episodes[entity_id] = []
            
        # Prune episodes outside the lookback window
        valid_episodes = []
        for ts, payload in self.episodes[entity_id]:
            if now - ts <= lookback_window_seconds:
                valid_episodes.append((ts, payload))
        
        self.episodes[entity_id] = valid_episodes
        
        # Aggregate all historical payloads + the current payload
        aggregated_text = " ".join([payload for _, payload in valid_episodes])
        aggregated_text += " " + current_payload
        
        # Normalize whitespace (replace multiple spaces with single space)
        import re
        aggregated_text_normalized = re.sub(r'\s+', ' ', aggregated_text).lower()
        aggregated_text_no_spaces = re.sub(r'\s+', '', aggregated_text).lower()
        
        for trigger in self.stitching_triggers:
            trigger_lower = trigger.lower()
            trigger_no_spaces = trigger_lower.replace(" ", "")
            if trigger_lower in aggregated_text_normalized or trigger_no_spaces in aggregated_text_no_spaces:
                logger.warning(f"Context Stitching Attack detected for entity {entity_id}: trigger '{trigger}'")
                return True
                
        return False
