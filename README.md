# Presidio-Based LLM Security Mini-Gateway
**CEN-451 Information Security — Assignment 2**

A modular security gateway that protects LLM-based systems from prompt injection, jailbreak attacks, and PII leakage using Microsoft Presidio and a custom scoring engine.

---

## Pipeline

```
User Input ──► Injection Detector ──► Presidio PII Analyzer ──► Policy Engine ──► Output
                    (score 0–1)         (custom recognizers)     ALLOW/MASK/BLOCK
```

---

## Repository Structure

```
llm-security-gateway/
├── main.py               # Interactive demo
├── gateway.py            # Core pipeline
├── injection_detector.py # Injection/jailbreak scoring engine
├── presidio_custom.py    # 3 custom Presidio recognizers
├── config.py             # Configurable thresholds & policy
├── evaluate.py           # Runs all 5 evaluation tables
└── requirements.txt
```

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/llm-security-gateway.git
cd llm-security-gateway
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate.bat       # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

---

## Running the Demo

```bash
python main.py
```

Type any prompt. Try:
- `What is the capital of France?` → ALLOW
- `Call me at +92-311-1234567` → MASK
- `Ignore all previous instructions` → BLOCK

Commands: `:help`, `:config`, `:quit`

---

## Reproducing the Evaluation Tables

```bash
python evaluate.py
```

Outputs 5 tables:
1. Scenario-Level Evaluation (12 scenarios)
2. Presidio Customization Validation
3. Threshold Calibration
4. Latency Summary
5. Performance Summary Metrics (Precision / Recall / F1)

---

## Presidio Customizations

| # | Type | Class | Entity |
|---|------|-------|--------|
| 1 | Custom Recognizer | `PakistaniPhoneRecognizer` | `PK_PHONE` |
| 1 | Custom Recognizer | `ApiKeyRecognizer` | `PK_API_KEY` |
| 1 | Custom Recognizer | `PakistaniNationalIdRecognizer` | `PK_NATIONAL_ID` |
| 2 | Context-Aware Scoring | `ContextAwareEmailRecognizer` | `EMAIL_ADDRESS` |
| 3 | Composite Detection | `CompositeIdentityRecognizer` | `IDENTITY_PAIR` |

---

## Configuration

All thresholds are in `config.py`:

```python
injection_threshold        = 0.55   # score >= this → BLOCK
pii_confidence_threshold   = 0.40   # Presidio results below this are ignored
high_sensitivity_entities  = [...]  # these PII types → BLOCK (not just MASK)
block_on_high_sensitivity  = True
```

---

## Environment

- Python 3.9+
- presidio-analyzer 2.2.354
- presidio-anonymizer 2.2.354
- spaCy en_core_web_lg

---

## Academic Note

Submitted for CEN-451 Assignment 2 — Bahria University BUIC.