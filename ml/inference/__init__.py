"""
ML Inference Components (stub)
==============================

The standalone XGBoost ML detector that previously lived here was removed
in the dead-code cleanup (2026-08).  The Analyzer never loaded or called it;
detection is handled entirely by the 4-layer pipeline in memgar/analyzer.py.

This package is retained only so ``import ml.inference`` doesn't crash in
downstream code that catches ImportError gracefully.
"""

__version__ = '2.0.0'
__all__: list = []
