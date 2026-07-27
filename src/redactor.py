import hashlib
import logging
import re

logger = logging.getLogger(__name__)

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    HAS_PRESIDIO = True
except Exception as e:
    logger.warning(f"Presidio/Spacy import blocked by system policy ({e}). Falling back to regex PII redactor.")
    HAS_PRESIDIO = False

class LogRedactor:
    def __init__(self):
        self.analyzer = None
        self.anonymizer = None

        if HAS_PRESIDIO:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                self.analyzer.analyze(text="warmup 127.0.0.1 admin@example.com", entities=["IP_ADDRESS", "PERSON", "EMAIL_ADDRESS"], language='en')
            except Exception as e:
                logger.warning(f"Presidio engine initialization notice ({e}). Using regex redactor.")
                self.analyzer = None
                self.anonymizer = None

    def _hash_text(self, text: str) -> str:
        """Create a deterministic ciphertext token from PII."""
        hashed = hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]
        return f"TOKEN:{hashed}"

    def redact(self, text: str) -> str:
        """Scan and redact sensitive PII (IPs, Person IDs, Emails)."""
        if self.analyzer is not None and self.anonymizer is not None:
            try:
                results = self.analyzer.analyze(
                    text=text,
                    entities=["IP_ADDRESS", "PERSON", "EMAIL_ADDRESS"],
                    language='en'
                )
                if results:
                    operators = {"DEFAULT": OperatorConfig("custom", {"lambda": self._hash_text})}
                    anonymized_result = self.anonymizer.anonymize(
                        text=text,
                        analyzer_results=results,
                        operators=operators
                    )
                    return anonymized_result.text
            except Exception as e:
                logger.error(f"Presidio redaction failed ({e}), falling back to regex.")

        # High-speed Regex PII Fallback (IP Addresses & Emails)
        redacted = text
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        def replace_ip(match):
            return self._hash_text(match.group(0))

        redacted = re.sub(ip_pattern, replace_ip, redacted)

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        def replace_email(match):
            return self._hash_text(match.group(0))

        redacted = re.sub(email_pattern, replace_email, redacted)

        return redacted
