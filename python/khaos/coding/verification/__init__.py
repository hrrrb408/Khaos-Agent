"""Project-aware verification pipeline."""

from khaos.coding.verification.detector import ProjectDetector
from khaos.coding.verification.models import VerificationPlan, VerificationStepResult
from khaos.coding.verification.planner import VerificationPlanner
from khaos.coding.verification.pipeline import VerificationPipeline

__all__ = ["ProjectDetector", "VerificationPipeline", "VerificationPlan", "VerificationPlanner", "VerificationStepResult"]
