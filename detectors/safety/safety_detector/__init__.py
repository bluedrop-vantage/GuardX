"""GuardX safety detector — llamaguard-shaped multi-category classifier.

M3 v1.3.0: multi-provider Judge — rubric-declared provider picks between
Together / DeepInfra / OpenAI / local vLLM / local Ollama, configured via
config/providers.yaml. Two response formats supported:
  * safety@1.0.0            — JSON rubric (works with any general instruct model)
  * safety_llamaguard@1.0.0 — native Meta Llama-Guard-3/4 format via DeepInfra
"""

__version__ = "1.3.0"
DETECTOR_ID = "safety-ensemble"
