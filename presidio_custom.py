"""
Presidio Customization Module — CEN-451 A2
Three required customizations:
  1. Custom recognizers  : PK phone, API key, PK National ID
  2. Context-aware scoring
  3. Composite entity detection (email + name proximity → IDENTITY_PAIR)
"""
import re
from typing import List, Optional

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    RecognizerResult,
    EntityRecognizer,
    AnalysisExplanation,
)
from presidio_analyzer import Pattern
from presidio_analyzer.nlp_engine import NlpArtifacts


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CUSTOM RECOGNIZERS
# ═══════════════════════════════════════════════════════════════════════════════

class PakistaniPhoneRecognizer(PatternRecognizer):
    """
    Recognizes Pakistani phone numbers.
    Formats: +92-3XX-XXXXXXX, 03XX-XXXXXXX, 03XXXXXXXXX, +923XXXXXXXXX
    Context words boost confidence (context-aware scoring).
    """

    PATTERNS = [
        Pattern("PK_PHONE_INTL",  r"\+92[-\s]?3[0-9]{2}[-\s]?[0-9]{7}\b", 0.80),
        Pattern("PK_PHONE_LOCAL", r"\b03[0-9]{2}[-\s]?[0-9]{7}\b",         0.75),
        Pattern("PK_PHONE_SHORT", r"\b3[0-9]{2}[0-9]{7}\b",                 0.50),
    ]

    CONTEXT = [
        "phone", "mobile", "cell", "contact", "call", "whatsapp",
        "number", "nmbr", "tel", "telephone", "ph", "mob",
    ]

    def __init__(self):
        super().__init__(
            supported_entity = "PK_PHONE",
            patterns         = self.PATTERNS,
            context          = self.CONTEXT,
            supported_language = "en",
            name             = "PakistaniPhoneRecognizer",
        )


class ApiKeyRecognizer(PatternRecognizer):
    """
    Recognizes common API key / secret token patterns.
    Context words apply strong boost.
    """

    PATTERNS = [
        Pattern("OPENAI_KEY",    r"\bsk-[A-Za-z0-9]{32,}\b",              0.90),
        Pattern("ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9\-_]{40,}\b",       0.95),
        Pattern("GENERIC_TOKEN", r"\b[A-Za-z0-9_\-]{32,64}\b",            0.40),   # low base
        Pattern("BEARER_TOKEN",  r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",       0.85),
        Pattern("AWS_KEY",       r"\bAKIA[0-9A-Z]{16}\b",                  0.95),
        Pattern("BASIC_B64",     r"Basic\s+[A-Za-z0-9+/]+=*",              0.75),
    ]

    CONTEXT = [
        "api", "key", "secret", "token", "auth", "authorization",
        "credential", "password", "passwd", "bearer", "access",
        "apikey", "api_key", "private", "sk-",
    ]

    def __init__(self):
        super().__init__(
            supported_entity   = "PK_API_KEY",
            patterns           = self.PATTERNS,
            context            = self.CONTEXT,
            supported_language = "en",
            name               = "ApiKeyRecognizer",
        )


class PakistaniNationalIdRecognizer(PatternRecognizer):
    """
    Recognizes Pakistani CNIC / NICOP numbers.
    Format: XXXXX-XXXXXXX-X  (13 digits with dashes)
    """

    PATTERNS = [
        Pattern("PK_CNIC",  r"\b[0-9]{5}-[0-9]{7}-[0-9]\b",  0.85),
        Pattern("PK_CNIC2", r"\b[0-9]{13}\b",                  0.40),  # no dashes — low confidence
    ]

    CONTEXT = [
        "cnic", "nicop", "national id", "identity card", "id card",
        "id number", "identity number", "computerised", "nic",
    ]

    def __init__(self):
        super().__init__(
            supported_entity   = "PK_NATIONAL_ID",
            patterns           = self.PATTERNS,
            context            = self.CONTEXT,
            supported_language = "en",
            name               = "PakistaniNationalIdRecognizer",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CONTEXT-AWARE SCORING  (built into PatternRecognizer via `context` param)
#    The PatternRecognizer automatically boosts scores when context words
#    appear near a match. Below is an explicit demonstration recognizer
#    that shows manual context boosting for the report.
# ═══════════════════════════════════════════════════════════════════════════════

class ContextAwareEmailRecognizer(EntityRecognizer):
    """
    Email recognizer with manual context-aware confidence adjustment.
    Base score 0.5; boosted to 0.85 when financial/medical context detected.
    """

    EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

    HIGH_CONTEXT_WORDS = [
        "bank", "payment", "invoice", "salary", "ssn", "patient",
        "medical", "prescription", "confidential", "private", "secret",
    ]

    def __init__(self):
        super().__init__(
            supported_entities = ["EMAIL_ADDRESS"],
            name               = "ContextAwareEmailRecognizer",
            supported_language = "en",
        )

    def load(self): pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts: Optional[NlpArtifacts] = None):
        results = []
        text_lower = text.lower()
        has_high_context = any(w in text_lower for w in self.HIGH_CONTEXT_WORDS)

        for m in self.EMAIL_RE.finditer(text):
            base_score    = 0.85
            boosted_score = 0.95 if has_high_context else base_score

            explanation = AnalysisExplanation(
                recognizer        = self.name,
                original_score    = base_score,
                pattern_name      = "EMAIL_PATTERN",
                pattern           = self.EMAIL_RE.pattern,
                validation_result = boosted_score,
                textual_explanation = (
                    f"Context boost applied (score {base_score}→{boosted_score})"
                    if has_high_context else
                    f"Base score {base_score} (no sensitive context)"
                ),
            )

            results.append(RecognizerResult(
                entity_type  = "EMAIL_ADDRESS",
                start        = m.start(),
                end          = m.end(),
                score        = boosted_score,
                analysis_explanation = explanation,
            ))
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# 3. COMPOSITE ENTITY DETECTION
#    Detects co-occurrence of PERSON + EMAIL/PHONE within 150 chars → IDENTITY_PAIR
# ═══════════════════════════════════════════════════════════════════════════════

class CompositeIdentityRecognizer(EntityRecognizer):
    """
    Detects composite identity leakage: PERSON name appearing within
    150 characters of a contact detail (email / phone).

    Emits a synthetic IDENTITY_PAIR entity that spans both matches.
    """

    PERSON_RE   = re.compile(
        r"\b(Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)?\s*[A-Z][a-z]+\s+[A-Z][a-z]+\b"
    )
    CONTACT_RE  = re.compile(
        r"(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        r"|\+?[0-9][0-9\s\-]{7,15}[0-9])"
    )
    PROXIMITY   = 150  # characters

    def __init__(self):
        super().__init__(
            supported_entities = ["IDENTITY_PAIR"],
            name               = "CompositeIdentityRecognizer",
            supported_language = "en",
        )

    def load(self): pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None):
        results  = []
        persons  = list(self.PERSON_RE.finditer(text))
        contacts = list(self.CONTACT_RE.finditer(text))

        for p in persons:
            for c in contacts:
                gap = abs(p.start() - c.start())
                if gap <= self.PROXIMITY:
                    span_start = min(p.start(), c.start())
                    span_end   = max(p.end(),   c.end())
                    results.append(RecognizerResult(
                        entity_type = "IDENTITY_PAIR",
                        start       = span_start,
                        end         = span_end,
                        score       = 0.85,
                        analysis_explanation = AnalysisExplanation(
                            recognizer        = self.name,
                            original_score    = 0.85,
                            pattern_name      = "COMPOSITE_PROXIMITY",
                            pattern           = f"gap={gap}",
                            validation_result = 0.85,
                            textual_explanation =
                                f"PERSON '{p.group().strip()}' + contact within {gap} chars",
                        ),
                    ))
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# ASSEMBLER
# ═══════════════════════════════════════════════════════════════════════════════

def build_analyzer() -> AnalyzerEngine:
    """Return a fully configured AnalyzerEngine with all custom recognizers."""
    engine = AnalyzerEngine()

    for recognizer in [
        PakistaniPhoneRecognizer(),
        ApiKeyRecognizer(),
        PakistaniNationalIdRecognizer(),
        ContextAwareEmailRecognizer(),
        CompositeIdentityRecognizer(),
    ]:
        engine.registry.add_recognizer(recognizer)

    return engine