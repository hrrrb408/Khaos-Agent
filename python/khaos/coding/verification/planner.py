from __future__ import annotations

from khaos.coding.verification.models import DetectedProject, VerificationPlan, VerificationStep


class VerificationPlanner:
    def plan(self, project: DetectedProject) -> VerificationPlan:
        root = project.root
        steps: list[VerificationStep] = []
        if project.ecosystem == "python":
            steps.append(VerificationStep("python-compile", "preflight", ("python", "-m", "compileall", "-q", "."), root, source="detected"))
            steps.append(VerificationStep("python-test", "unit-test", ("python", "-m", "pytest", "-q"), root, source="detected"))
        elif project.ecosystem == "node":
            steps.append(VerificationStep("node-test", "unit-test", ("npm", "test"), root, source="manifest"))
        elif project.ecosystem == "go":
            steps.append(VerificationStep("go-vet", "lint", ("go", "vet", "./..."), root))
            steps.append(VerificationStep("go-test", "unit-test", ("go", "test", "./..."), root))
        elif project.ecosystem == "rust":
            steps.append(VerificationStep("rust-check", "build", ("cargo", "check"), root))
            steps.append(VerificationStep("rust-test", "unit-test", ("cargo", "test"), root))
        else:
            return VerificationPlan((), ("no-safe-plan",))
        return VerificationPlan(tuple(steps))
