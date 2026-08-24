"""Project-aware verification pipeline."""

from khaos.coding.verification.detector import ProjectDetector
from khaos.coding.verification.models import VerificationPlan, VerificationStepResult
from khaos.coding.verification.pipeline import (
    VerificationMemoryOutcome,
    VerificationPipeline,
)
from khaos.coding.verification.planner import VerificationPlanner

__all__ = ["ProjectDetector", "VerificationMemoryOutcome", "VerificationPipeline", "VerificationPlan", "VerificationPlanner", "VerificationStepResult"]
