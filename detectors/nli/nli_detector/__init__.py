"""GuardX NLI groundedness detector (spec §4.3.3).

Tier-1 in M3 first pass: hosted LLM judge scores each claim against the
provided context. Tier-2 replaces this with a fast ONNX MNLI cross-encoder
and demotes the judge to a borderline-only tier.
"""

__version__ = "2.1.0"
DETECTOR_ID = "nli-groundedness"
