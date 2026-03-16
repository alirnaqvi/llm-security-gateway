"""
Injection & Jailbreak Detection Module
Scores user input [0.0 – 1.0]; higher = more suspicious.
"""
import re
from typing import Tuple, List
from dataclasses import dataclass


@dataclass
class SignalRule:
    name:    str
    pattern: re.Pattern
    weight:  float


# ── Signal library ────────────────────────────────────────────────────────────
_RULES: List[SignalRule] = [

    # -- Prompt Injection --
    SignalRule("ignore_instructions",
               re.compile(r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)", re.I),
               0.80),
    SignalRule("new_instructions",
               re.compile(r"(disregard|forget|override)\s+(all\s+)?(your\s+)?(instructions?|guidelines?|rules?)", re.I),
               0.75),
    SignalRule("act_as",
               re.compile(r"\bact\s+as\b.{0,50}(without|no)\s+(restriction|filter|limit|guideline)", re.I),
               0.65),
    SignalRule("you_are_now",
               re.compile(r"\byou\s+are\s+now\b.{0,40}(unrestricted|jailbroken|free|unfiltered)", re.I),
               0.70),

    # -- Jailbreak / DAN patterns --
    SignalRule("dan_keyword",
               re.compile(r"\bD\.?A\.?N\.?\b", re.I),
               0.85),
    SignalRule("jailbreak_keyword",
               re.compile(r"\b(jailbreak|jail.?break)\b", re.I),
               0.80),
    SignalRule("developer_mode",
               re.compile(r"\bdeveloper\s+mode\b", re.I),
               0.65),
    SignalRule("do_anything_now",
               re.compile(r"\bdo\s+anything\s+now\b", re.I),
               0.80),
    SignalRule("token_manipulation",
               re.compile(r"\b(token|prompt)\s+(smuggling|injection|leaking|hijack)", re.I),
               0.75),

    # -- System Prompt Extraction --
    SignalRule("repeat_system_prompt",
               re.compile(r"(repeat|print|output|reveal|show|display)\s+(your\s+)?(system\s+prompt|initial\s+prompt|instructions?)", re.I),
               0.75),
    SignalRule("what_were_you_told",
               re.compile(r"what\s+(were|are)\s+you\s+(told|instructed|trained|programmed)", re.I),
               0.60),
    SignalRule("start_with_sure",
               re.compile(r"start\s+your\s+(reply|response|answer)\s+with\s+[\"']?sure", re.I),
               0.50),

    # -- Role / Persona Escape --
    SignalRule("pretend_no_rules",
               re.compile(r"pretend\s+(you\s+)?(have\s+no|don.t\s+have)\s+(rules?|restrictions?|guidelines?)", re.I),
               0.70),
    SignalRule("simulate_evil",
               re.compile(r"(simulate|roleplay|pretend)\s+(you\s+are\s+)?(an?\s+)?(evil|malicious|uncensored|unethical)\s+(ai|bot|assistant|model)", re.I),
               0.75),

    # -- Encoding / Obfuscation --
    SignalRule("base64_decode",
           re.compile(r"base64", re.I),
           0.50),
    SignalRule("execute_decode",
           re.compile(r"(decode|execute|run|eval).{0,30}(base64|encoded|payload)", re.I),
           0.55),
    SignalRule("rot13",
               re.compile(r"\brot.?13\b", re.I),
               0.40),
    SignalRule("hex_encoded_inject",
               re.compile(r"(0x[0-9a-f]{2}\s*){6,}", re.I),   # long hex sequences
               0.40),

    # -- Indirect / Payload Injection --
    SignalRule("system_tag_spoof",
               re.compile(r"<\s*(system|assistant|human|user)\s*>", re.I),
               0.60),
    SignalRule("triple_hash_inject",
               re.compile(r"###\s*(system|instruction|override)", re.I),
               0.55),
]


class InjectionDetector:
    """
    Scores text for prompt injection / jailbreak signals.
    Returns (score, matched_rule_name).

    Scoring formula: 1 - ∏(1 - wᵢ) so multiple weak signals combine,
    but a single strong signal can still dominate.
    """

    def __init__(self, threshold: float = 0.55):
        self.threshold = threshold
        self.rules     = _RULES

    def score(self, text: str) -> Tuple[float, str]:
        matched: List[SignalRule] = []
        for rule in self.rules:
            if rule.pattern.search(text):
                matched.append(rule)

        if not matched:
            return 0.0, "clean"

        # Probabilistic combination
        combined = 1.0
        for rule in matched:
            combined *= (1.0 - rule.weight)
        final_score = round(1.0 - combined, 4)

        reason = ", ".join(r.name for r in matched)
        return final_score, reason

    def explain(self, text: str) -> dict:
        """Return detailed breakdown for debugging / report generation."""
        score, reason = self.score(text)
        return {
            "score":    score,
            "decision": "BLOCK" if score >= self.threshold else "PASS",
            "signals":  reason.split(", ") if reason != "clean" else [],
        }