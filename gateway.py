"""
Presidio-Based LLM Security Mini-Gateway
CEN-451 Assignment 2 - Information Security
"""

import time
import re
import json
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from injection_detector import InjectionDetector
from presidio_custom import build_analyzer
from config import GatewayConfig


class PolicyDecision(str, Enum):
    ALLOW  = "ALLOW"
    MASK   = "MASK"
    BLOCK  = "BLOCK"


@dataclass
class GatewayResult:
    decision:         PolicyDecision
    sanitized_text:   Optional[str]
    injection_score:  float
    pii_entities:     list
    latency_ms:       float
    reason:           str
    raw_input:        str
    masked_output:    Optional[str] = None


class LLMSecurityGateway:
    """
    Pipeline: Input → Injection Detection → Presidio PII Analysis → Policy → Output
    """

    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config    = config or GatewayConfig()
        self.detector  = InjectionDetector(threshold=self.config.injection_threshold)
        self.analyzer  = build_analyzer()
        self.anonymizer = AnonymizerEngine()

    # ------------------------------------------------------------------
    def process(self, user_input: str) -> GatewayResult:
        t_start = time.perf_counter()

        # ── Step 1: Injection / Jailbreak Detection ────────────────────
        inj_score, inj_reason = self.detector.score(user_input)

        if inj_score >= self.config.injection_threshold:
            latency = (time.perf_counter() - t_start) * 1000
            return GatewayResult(
                decision        = PolicyDecision.BLOCK,
                sanitized_text  = None,
                injection_score = inj_score,
                pii_entities    = [],
                latency_ms      = round(latency, 2),
                reason          = f"Injection detected ({inj_reason}), score={inj_score:.2f}",
                raw_input       = user_input,
            )

        # ── Step 2: Presidio PII Analysis ─────────────────────────────
        results = self.analyzer.analyze(
            text     = user_input,
            language = "en",
        )

        # Apply confidence threshold
        results = [
            r for r in results
            if r.score >= self.config.pii_confidence_threshold
            and r.entity_type not in self.config.ignored_entities
        ]

        # ── Step 3: Policy Decision ────────────────────────────────────
        high_sensitivity = [
            r for r in results
            if r.entity_type in self.config.high_sensitivity_entities
        ]

        if high_sensitivity and self.config.block_on_high_sensitivity:
            latency = (time.perf_counter() - t_start) * 1000
            return GatewayResult(
                decision        = PolicyDecision.BLOCK,
                sanitized_text  = None,
                injection_score = inj_score,
                pii_entities    = [self._fmt(r) for r in results],
                latency_ms      = round(latency, 2),
                reason          = f"High-sensitivity PII detected: {[r.entity_type for r in high_sensitivity]}",
                raw_input       = user_input,
            )

        masked_text = user_input
        if results:
            decision   = PolicyDecision.MASK
            masked_text = self._mask(user_input, results)
            reason     = f"PII masked: {list({r.entity_type for r in results})}"
        else:
            decision = PolicyDecision.ALLOW
            reason   = "No threats detected"

        latency = (time.perf_counter() - t_start) * 1000
        return GatewayResult(
            decision        = decision,
            sanitized_text  = masked_text,
            injection_score = inj_score,
            pii_entities    = [self._fmt(r) for r in results],
            latency_ms      = round(latency, 2),
            reason          = reason,
            raw_input       = user_input,
            masked_output   = masked_text if results else None,
        )

    # ------------------------------------------------------------------
    def _mask(self, text: str, results: list) -> str:
        operators = {
            r.entity_type: OperatorConfig("replace", {"new_value": f"<{r.entity_type}>"})
            for r in results
        }
        anonymized = self.anonymizer.anonymize(
            text            = text,
            analyzer_results = results,
            operators        = operators,
        )
        return anonymized.text

    @staticmethod
    def _fmt(r: RecognizerResult) -> dict:
        return {
            "entity_type": r.entity_type,
            "score":       round(r.score, 3),
            "start":       r.start,
            "end":         r.end,
        }