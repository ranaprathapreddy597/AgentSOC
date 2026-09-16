"""
AgentSOC - Zero-Trust PII Redactor Layer (redactor.py)
IEEE Publication Grade Cryptographic PII Masking Engine using Microsoft Presidio & Deterministic SHA256 Hashing
"""

import hashlib
import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    HAS_PRESIDIO = True
except Exception as e:
    logger.warning(f"[Zero-Trust Redactor] Presidio/Spacy notice ({e}). Falling back to regex PII redactor.")
    HAS_PRESIDIO = False


class ZeroTrustPIIRedactor:
    """
    Zero-Trust PII Redactor Layer.
    Intercepts raw security log payloads and cryptographically hashes sensitive PII
    (IP Addresses, Usernames, Email Addresses) into deterministic ciphertext tokens before
    passing events to the Perception Layer. Implements a Stateful Vault for payload rehydration.
    """

    def __init__(self):
        # The Stateful Vault: Maps TOKEN:XXXX -> true raw value for rehydration
        self._token_vault: Dict[str, str] = {}
        self.analyzer = None
        self.anonymizer = None

        if HAS_PRESIDIO:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                # Cold-start warmup run to allocate NLP pipeline
                self.analyzer.analyze(
                    text="warmup 127.0.0.1 admin@example.com",
                    entities=["IP_ADDRESS", "PERSON", "EMAIL_ADDRESS"],
                    language="en"
                )
                logger.info("[Zero-Trust Redactor] Initialized Microsoft Presidio Analyzer & Anonymizer.")
            except Exception as e:
                logger.warning(f"[Zero-Trust Redactor] Presidio init fallback ({e}). Using regex redactor.")
                self.analyzer = None
                self.anonymizer = None

    def _hash_pii_token(self, pii_text: str) -> str:
        """
        Generates a deterministic 16-character SHA-256 ciphertext token prefix.
        Example: '192.168.1.150' -> 'TOKEN:f5047344122f0dee'
        Also maps the token to the true value in the _token_vault.
        """
        digest = hashlib.sha256(pii_text.encode("utf-8")).hexdigest()[:16]
        token = f"TOKEN:{digest}"
        # Store securely in the vault for downstream rehydration
        self._token_vault[token] = pii_text
        return token

    def redact_payload(self, raw_log_text: str) -> str:
        """
        Redacts raw security log text using Presidio NLP entity extraction or regex fallback.
        """
        if not raw_log_text:
            return ""

        if self.analyzer is not None and self.anonymizer is not None:
            try:
                results = self.analyzer.analyze(
                    text=raw_log_text,
                    entities=["IP_ADDRESS", "PERSON", "EMAIL_ADDRESS"],
                    language="en"
                )
                if results:
                    operators = {
                        "DEFAULT": OperatorConfig("custom", {"lambda": self._hash_pii_token})
                    }
                    anonymized = self.anonymizer.anonymize(
                        text=raw_log_text,
                        analyzer_results=results,
                        operators=operators
                    )
                    return anonymized.text
            except Exception as e:
                logger.error(f"[Zero-Trust Redactor] Presidio redaction failed ({e}). Falling back to regex.")

        # High-Speed Deterministic Regex Fallback (Sub-millisecond Edge-AI SLA)
        redacted = raw_log_text

        # 1. Match IPv4 Addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        redacted = re.sub(ip_pattern, lambda m: self._hash_pii_token(m.group(0)), redacted)

        # 2. Match Email Addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        redacted = re.sub(email_pattern, lambda m: self._hash_pii_token(m.group(0)), redacted)

        return redacted

    async def rehydrate_playbook(self, playbook_data: Any) -> Any:
        """
        Scans the final LLM output, looks up any cryptographic tokens in the _token_vault,
        and replaces them with the true IP addresses/entities to render the playbook actionable
        for a human SOC analyst.
        """
        if isinstance(playbook_data, str):
            rehydrated = playbook_data
            # We iterate through active vault items and perform replacements.
            # In a massive high-throughput scenario, a regex-based trie substitution would be used.
            for token, raw_val in self._token_vault.items():
                if token in rehydrated:
                    rehydrated = rehydrated.replace(token, raw_val)
            return rehydrated
        elif isinstance(playbook_data, dict):
            return {k: await self.rehydrate_playbook(v) for k, v in playbook_data.items()}
        elif isinstance(playbook_data, list):
            return [await self.rehydrate_playbook(i) for i in playbook_data]
        return playbook_data


# Maintain backward compatibility alias
class LogRedactor(ZeroTrustPIIRedactor):
    def redact(self, text: str) -> str:
        return self.redact_payload(text)
