"""presidio-ensemble PII detector.

M1 ships Layer 1 (regex) + Layer 3 (context scoring). Layer 2 (ONNX NER) is
scaffolded for later — the ensemble merges spans regardless of source.
"""

__version__ = "1.4.0"
DETECTOR_ID = "presidio-ensemble"
