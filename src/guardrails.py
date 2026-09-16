"""
AgentSOC - SLM Guardrail Layer (guardrails.py)
IEEE Publication Grade Prompt Injection & Semantic Override Detection.
Integrates a DeBERTa-v3 classifier for semantic detection with a sub-15ms heuristic fallback.
"""

import time
import re
import logging
import copy
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

try:
    import torch
    from transformers import pipeline
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class SLMGuardrail:
    """
    SLMGuardrail Layer.
    Scans the Enriched Incident Object (EIO) for prompt injections and adversarial overrides 
    (mimicking Microsoft Prompt Shields / Prompt-Guard behaviors) before it reaches the generative LLM.
    """

    def __init__(self, 
                 model_name: str = "ProtectAI/deberta-v3-base-prompt-injection-v2", 
                 confidence_threshold: float = 0.85,
                 max_latency_ms: float = 15.0):
        self.confidence_threshold = confidence_threshold
        self.max_latency_ms = max_latency_ms
        self.classifier = None
        
        if HAS_TRANSFORMERS:
            try:
                # Load lightweight DeBERTa-v3 classification model optimized for prompt injection detection.
                # In a true edge deployment, this would use ONNX/TensorRT for speed, but transformers is used here for research.
                self.classifier = pipeline(
                    "text-classification", 
                    model=model_name,
                    device=-1  # Force CPU to avoid CUDA initialization overhead in standard environments
                )
                logger.info(f"[SLMGuardrail] Successfully loaded Transformer model: {model_name}")
            except Exception as e:
                logger.warning(f"[SLMGuardrail] Transformer initialization failed ({e}). Defaulting to heuristic fallback.")
                self.classifier = None
        else:
            logger.warning("[SLMGuardrail] PyTorch/Transformers not installed. Running in pure heuristic fallback mode.")

        # Lightning-fast regex fallback compiled for Red-Team datasets
        self.fallback_pattern = re.compile(
            r"(ignore previous instructions|system prompt|bypass|override|you are now|grant admin|drop table|<\s*script)",
            re.IGNORECASE
        )

    def _evaluate_text(self, text: str) -> Tuple[bool, float, str]:
        """
        Evaluates a text string using the DeBERTa-v3 model or heuristic fallback.
        Returns: (is_malicious, confidence_score, detection_method)
        """
        if not text or not isinstance(text, str):
            return False, 0.0, "none"

        start_time = time.perf_counter()

        # 1. Attempt Transformer Model Classification
        if self.classifier:
            try:
                # Transformer inference
                result = self.classifier(text[:512]) # Truncate to max sequence length for speed
                latency_ms = (time.perf_counter() - start_time) * 1000
                
                # Check if transformer took too long. If so, log a warning for SLA monitoring.
                if latency_ms > self.max_latency_ms:
                    logger.debug(f"[SLMGuardrail] Transformer inference exceeded SLA ({latency_ms:.2f}ms > {self.max_latency_ms}ms).")

                label = result[0]['label']
                score = result[0]['score']

                # Map standard prompt-injection model labels
                # Note: Exact label string depends on the model. "INJECTION", "LABEL_1", etc.
                if (label.upper() == "INJECTION" or label == "LABEL_1") and score >= self.confidence_threshold:
                    return True, score, "transformer"
                
                # If the model is highly confident it's safe, return early.
                if score >= self.confidence_threshold:
                    return False, score, "transformer"
            
            except Exception as e:
                logger.error(f"[SLMGuardrail] Inference error ({e}). Engaging heuristic fallback.")

        # 2. Lightning-Fast Heuristic Fallback
        # Engaged if transformers is missing, failed, or we need a secondary check.
        match = self.fallback_pattern.search(text)
        if match:
            # Heuristic matches are treated as 99% confidence injections
            return True, 0.99, f"heuristic (matched: '{match.group(0)}')"

        return False, 0.0, "heuristic"

    def _recursive_sanitize(self, data: Any, current_flags: list) -> Any:
        """Recursively scans all string fields within an object/dict/list."""
        if isinstance(data, str):
            is_malicious, confidence, method = self.evaluate_text(data)
            if is_malicious:
                logger.warning(f"[SLMGuardrail] Prompt injection detected via {method} (Confidence: {confidence:.2f}). Sanitizing string.")
                current_flags.append("PROMPT_INJECTION_DETECTED")
                return "[REDACTED_MALICIOUS_PROMPT_INJECTION]"
            return data
            
        elif isinstance(data, dict):
            return {k: self._recursive_sanitize(v, current_flags) for k, v in data.items()}
            
        elif isinstance(data, list):
            return [self._recursive_sanitize(item, current_flags) for item in data]
            
        return data

    # Expose the internal method for direct text evaluation if needed
    def evaluate_text(self, text: str) -> Tuple[bool, float, str]:
        return self._evaluate_text(text)

    async def sanitize_eio(self, eio: Dict[str, Any]) -> Dict[str, Any]:
        """
        Asynchronous sanitization of the Enriched Incident Object (EIO).
        Scans string fields without crashing on errors. Flags malicious payloads 
        and explicitly redacts the malicious string.
        """
        logger.debug(f"[SLMGuardrail] Starting sanitization for EIO: {eio.get('incident_id', 'UNKNOWN')}")
        
        # Deep copy to avoid mutating the original EIO reference unexpectedly
        sanitized_eio = copy.deepcopy(eio)
        new_flags = []

        try:
            # Recursively traverse and sanitize all nested string payloads
            for key, value in sanitized_eio.items():
                if key == "security_flags":
                    continue # Skip existing flags list during scan
                
                sanitized_eio[key] = self._recursive_sanitize(value, new_flags)

            # If any prompt injections were found in the EIO, append the flag
            if new_flags:
                # Deduplicate and append to existing flags
                existing_flags = sanitized_eio.get("security_flags", [])
                if isinstance(existing_flags, list) and "PROMPT_INJECTION_DETECTED" not in existing_flags:
                    existing_flags.append("PROMPT_INJECTION_DETECTED")
                    sanitized_eio["security_flags"] = existing_flags
                
                # Assign explicitly in case the field was missing or wasn't a list
                elif "guardrail_flag" not in sanitized_eio:
                    sanitized_eio["guardrail_flag"] = "PROMPT_INJECTION_DETECTED"

        except Exception as e:
            # Never crash the pipeline on a guardrail failure
            logger.error(f"[SLMGuardrail] Unexpected error during EIO sanitization: {e}")
            
        return sanitized_eio
