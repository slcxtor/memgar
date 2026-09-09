"""
ML System for Memgar
====================

Machine learning components for advanced threat detection.

Components:
- training/: Model training pipeline (XGBoostTrainingPipeline)
- data/: Training and calibration datasets
- artifacts/: Trained models and calibration reports

The detector itself lives in the package proper, at
``memgar.ml_semantic_detector``; import it from there. The training
pipeline is imported directly where it is used::

    from ml.training.train import XGBoostTrainingPipeline
"""

__version__ = '1.0.0'

__all__: list[str] = []
