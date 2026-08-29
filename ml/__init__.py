"""
ML System for Memgar
====================

Machine learning components for advanced threat detection.

Components:
- adversarial/: Attack variant generation and curation
- data/: Training and calibration datasets
- artifacts/: Calibration outputs
- continuous_learning.py: Feedback tracking and drift detection

The standalone XGBoost training pipeline and MLSemanticDetector were removed
in the dead-code cleanup (2026-08) — the Analyzer never loaded or called the
trained model.  Detection is handled entirely by the 4-layer pipeline in
memgar/analyzer.py.
"""

__version__ = '2.0.0'
__author__ = 'Memgar Security Team'

__all__: list = []
