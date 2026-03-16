from dataclasses import dataclass, field
from typing import List

@dataclass
class GatewayConfig:
    injection_threshold: float = 0.55
    pii_confidence_threshold: float = 0.4

    high_sensitivity_entities: List[str] = field(default_factory=lambda: [
        "CREDIT_CARD",
        "CRYPTO",
        "IBAN_CODE",
        "PK_API_KEY",
        "PK_NATIONAL_ID",
    ])

    # Add these two lines — ignore low-risk geographic entities
    ignored_entities: List[str] = field(default_factory=lambda: [
        "LOCATION", "DATE_TIME", "NRP",
    ])

    block_on_high_sensitivity: bool = True