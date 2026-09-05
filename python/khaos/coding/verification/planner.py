from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from khaos.coding.verification.contracts import (
    VerificationCheck,
    VerificationCheckKind,
    VerificationCost,
    VerificationPlan,
    VerificationReason,
    VerificationRisk,
    VerificationStage,
)
from khaos.coding.verification.impact import EditImpact
from khaos.coding.verification.models import DetectedProject, VerificationStep
from khaos.coding.verification.models import VerificationPlan as LegacyVerificationPlan
from khaos.coding.verification.profile import (
    VerificationCommandSpec,
    VerificationProfile,
)
from khaos.security.protocol_boundary import canonical_digest

_SOURCE_SUFFIXES = frozenset({
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
})
_SECURITY_PATH_PARTS = frozenset(
    {
        "approval",
        "auth",
        "authentication",
        "authorization",
        "credential",
        "execution",
        "permission",
        "permissions",
        "sandbox",
        "security",
        "workspace",
    }
)


@dataclass(frozen=True, slots=True)
class AutonomousPlannerLimits:
    """Hard bounds for one autonomous verification plan."""

    max_checks: int = 16
    max_total_seconds: float = 600.0
    max_check_timeout: float = 120.0
    max_output_bytes: int = 65_536
    max_repair_cycles: int = 3

    def __post_init__(self) -> None:
        if type(self.max_checks) is not int or self.max_checks <= 0:
            raise ValueError("max_checks must be positive")
        if (
            type(self.max_total_seconds) not in (int, float)
            or not math.isfinite(float(self.max_total_seconds))
            or self.max_total_seconds < 0.1
        ):
            raise ValueError("max_total_seconds must be finite and at least 0.1")
        if (
            type(self.max_check_timeout) not in (int, float)
            or not math.isfinite(float(self.max_check_timeout))
            or self.max_check_timeout < 0.1
        ):
            raise ValueError("max_check_timeout must be finite and at least 0.1")
        if type(self.max_output_bytes) is not int or self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if type(self.max_repair_cycles) is not int or self.max_repair_cycles < 0:
            raise ValueError("max_repair_cycles must be non-negative")

    @classmethod
    def from_config(cls, config: Mapping[str, object]) -> AutonomousPlannerLimits:
        """Read bounded verification settings without allowing a widening.

        Project/user configuration can narrow the immutable code defaults, but
        it cannot increase them.  Both long and short spellings are accepted
        because the M8.3 design used both names during migration.
        """
        if not isinstance(config, Mapping):
            raise TypeError("verification config must be a mapping")
        coding = config.get("coding", {})
        if not isinstance(coding, Mapping):
            raise TypeError("coding config must be a mapping")
        verification = coding.get("verification", {})
        if not isinstance(verification, Mapping):
            raise TypeError("coding.verification config must be a mapping")
        defaults = cls()

        def bounded_number(
            keys: tuple[str, ...],
            default: float,
            *,
            integral: bool,
            minimum: float,
        ) -> float:
            values: list[float] = []
            for key in keys:
                if key not in verification:
                    continue
                value = verification[key]
                if integral:
                    if type(value) is not int:
                        raise ValueError(f"{key} must be an integer")
                elif type(value) not in (int, float):
                    raise ValueError(f"{key} must be numeric")
                if value < minimum:
                    raise ValueError(f"{key} is below its minimum")
                values.append(float(value))
            if not values:
                return float(default)
            return min(values + [default])

        max_total = bounded_number(
            ("max_total_seconds", "max_total_verification_seconds"),
            defaults.max_total_seconds,
            integral=False,
            minimum=0.1,
        )
        max_timeout = bounded_number(
            ("max_check_timeout",),
            defaults.max_check_timeout,
            integral=False,
            minimum=0.1,
        )
        return cls(
            max_checks=int(
                bounded_number(
                    ("max_checks",),
                    defaults.max_checks,
                    integral=True,
                    minimum=1,
                )
            ),
            max_total_seconds=float(max_total),
            max_check_timeout=float(max_timeout),
            max_output_bytes=int(
                bounded_number(
                    ("max_check_output_bytes", "max_output_bytes"),
                    defaults.max_output_bytes,
                    integral=True,
                    minimum=1,
                )
            ),
            max_repair_cycles=int(
                bounded_number(
                    ("max_repair_cycles",),
                    defaults.max_repair_cycles,
                    integral=True,
                    minimum=0,
                )
            ),
        )


class VerificationPlanner:
    def plan(self, project: DetectedProject) -> LegacyVerificationPlan:
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
            return LegacyVerificationPlan((), ("no-safe-plan",))
        return LegacyVerificationPlan(tuple(steps))


class AutonomousVerificationPlanner:
    """Select a deterministic, generation-bound verification plan.

    The planner only transforms typed ``VerificationProfile`` commands.  It
    never accepts an argv from the model, README prose, package-script text,
    or a free-form user command.
    """

    def __init__(self, limits: AutonomousPlannerLimits | None = None) -> None:
        self.limits = limits or AutonomousPlannerLimits()

    def plan(
        self,
        impact: EditImpact,
        profile: VerificationProfile,
        *,
        workspace_generation: int | None = None,
    ) -> VerificationPlan:
        """Create a stable plan from direct impact and trusted profile data."""
        if type(impact) is not EditImpact:
            raise TypeError("impact must be an EditImpact")
        if type(profile) is not VerificationProfile:
            raise TypeError("profile must be a VerificationProfile")
        if not profile.is_valid():
            raise ValueError("verification profile digest is invalid")
        current_workspace_generation = (
            impact.resulting_generation
            if workspace_generation is None
            else workspace_generation
        )
        if type(current_workspace_generation) is not int or current_workspace_generation < 0:
            raise ValueError("workspace_generation must be non-negative")

        risk = self._risk(impact)
        reasons = self._reasons(impact, profile, risk)
        checks: list[VerificationCheck] = []
        source_paths = tuple(
            path
            for path in impact.changed_paths
            if not _looks_like_test(path)
            and Path(path).suffix.casefold() in _SOURCE_SUFFIXES
        )
        test_paths = tuple(
            sorted(set(impact.related_tests) | {path for path in impact.changed_paths if _looks_like_test(path)})
        )
        if not impact.is_docs_only:
            checks.extend(self._structural_checks(impact, profile))

        selected_targeted = False
        selected_package = False
        for spec in profile.commands:
            if not self._language_matches(spec, impact, profile):
                continue
            if spec.kind in {VerificationCheckKind.LINT, VerificationCheckKind.FORMAT}:
                if impact.is_test_only:
                    continue
                checks.append(
                    self._from_spec(
                        spec,
                        stage=VerificationStage.STATIC,
                        profile_digest=profile.profile_digest,
                        target_paths=source_paths,
                        target_symbols=impact.changed_symbols,
                        required=True,
                        reason_codes=("changed-source",),
                        cost=VerificationCost.CHEAP,
                    )
                )
            elif spec.kind is VerificationCheckKind.TYPECHECK:
                if impact.is_test_only:
                    continue
                checks.append(
                    self._from_spec(
                        spec,
                        stage=VerificationStage.TYPECHECK,
                        profile_digest=profile.profile_digest,
                        target_paths=source_paths,
                        target_symbols=impact.changed_symbols,
                        required=risk is not VerificationRisk.LOW,
                        reason_codes=("changed-source",),
                        cost=VerificationCost.NORMAL,
                    )
                )
            elif spec.kind in {
                VerificationCheckKind.PACKAGE_TEST,
                VerificationCheckKind.TARGETED_TEST,
            }:
                if test_paths and not impact.is_docs_only:
                    checks.append(
                        self._from_spec(
                            spec,
                            stage=VerificationStage.TARGETED,
                            profile_digest=profile.profile_digest,
                            target_paths=test_paths,
                            target_symbols=impact.changed_symbols,
                            required=True,
                            reason_codes=("related-tests",),
                            cost=VerificationCost.NORMAL,
                        )
                    )
                    selected_targeted = True
                elif not impact.is_docs_only and (risk is not VerificationRisk.LOW):
                    checks.append(
                        self._from_spec(
                            spec,
                            stage=VerificationStage.MODULE,
                            profile_digest=profile.profile_digest,
                            target_paths=(),
                            target_symbols=impact.changed_symbols,
                            required=True,
                            reason_codes=("no-related-tests",),
                            cost=VerificationCost.EXPENSIVE,
                        )
                    )
                    selected_package = True
            elif spec.kind is VerificationCheckKind.BUILD:
                if impact.build_config_paths or impact.config_paths or risk is VerificationRisk.HIGH:
                    checks.append(
                        self._from_spec(
                            spec,
                            stage=VerificationStage.INTEGRATION,
                            profile_digest=profile.profile_digest,
                            target_paths=(),
                            target_symbols=impact.changed_symbols,
                            required=True,
                            reason_codes=("build-or-config-impact",),
                            cost=VerificationCost.EXPENSIVE,
                        )
                    )
            elif spec.kind is VerificationCheckKind.INTEGRATION_TEST:
                if risk is VerificationRisk.HIGH:
                    checks.append(
                        self._from_spec(
                            spec,
                            stage=VerificationStage.INTEGRATION,
                            profile_digest=profile.profile_digest,
                            target_paths=(),
                            target_symbols=impact.changed_symbols,
                            required=True,
                            reason_codes=("high-risk-impact",),
                            cost=VerificationCost.EXPENSIVE,
                        )
                    )
            elif spec.kind is VerificationCheckKind.REGRESSION and risk is VerificationRisk.HIGH:
                checks.append(
                    self._from_spec(
                        spec,
                        stage=VerificationStage.REGRESSION,
                        profile_digest=profile.profile_digest,
                        target_paths=(),
                        target_symbols=impact.changed_symbols,
                        required=True,
                        reason_codes=("high-risk-regression",),
                        cost=VerificationCost.EXPENSIVE,
                    )
                )
            elif spec.kind is VerificationCheckKind.CUSTOM_PROJECT_CHECK:
                if not impact.is_docs_only:
                    checks.append(
                        self._from_spec(
                            spec,
                            stage=(
                                VerificationStage.INTEGRATION
                                if risk is VerificationRisk.HIGH
                                else VerificationStage.MODULE
                            ),
                            profile_digest=profile.profile_digest,
                            target_paths=(),
                            target_symbols=impact.changed_symbols,
                            required=True,
                            reason_codes=("trusted-custom-project-check",),
                            cost=VerificationCost.EXPENSIVE,
                        )
                    )

        if impact.is_test_only and not selected_targeted:
            reasons = (*reasons, VerificationReason("test-only-no-related-command", "No trusted targeted test command was available."))
        if not impact.is_docs_only and not checks:
            reasons = (*reasons, VerificationReason("no-safe-check", "No trusted verification command matched the changed scope."))
        if impact.uncertainty and not selected_package:
            reasons = (*reasons, VerificationReason("uncertainty-broadens-scope", "Incomplete impact evidence requires the broadest trusted checks available."))

        checks = self._deduplicate(checks)
        if len(checks) > self.limits.max_checks:
            checks = self._prioritize(checks)[: self.limits.max_checks]
            reasons = (*reasons, VerificationReason("max-checks-truncated", "Verification plan reached its hard check bound."))
        checks = self._fit_time_budget(checks)
        reasons = _unique_reasons(reasons)
        checks.sort(key=_check_sort_key)
        seed = canonical_digest(
            {
                "workspace_id": impact.workspace_id,
                "workspace_generation": current_workspace_generation,
                "repository_generation": impact.repository_generation,
                "impact_digest": impact.digest,
                "profile_digest": profile.profile_digest,
                "checks": tuple(check.to_payload() for check in checks),
                "risk": risk.value,
                "reasons": tuple(item.to_payload() for item in reasons),
            }
        )
        return VerificationPlan(
            plan_id=f"m83-plan-{seed[:24]}",
            workspace_id=impact.workspace_id,
            workspace_generation=current_workspace_generation,
            repository_generation=impact.repository_generation,
            impact_digest=impact.digest,
            profile_id=profile.profile_id,
            profile_digest=profile.profile_digest,
            checks=tuple(checks),
            risk=risk,
            reasons=tuple(reasons),
            edit_transaction_id=impact.transaction_id,
            edit_transaction_digest=impact.transaction_digest,
            max_checks=self.limits.max_checks,
            max_total_seconds=self.limits.max_total_seconds,
            max_output_bytes=self.limits.max_output_bytes,
        )

    def _structural_checks(
        self,
        impact: EditImpact,
        profile: VerificationProfile,
    ) -> list[VerificationCheck]:
        checks: list[VerificationCheck] = []
        for path in impact.changed_paths:
            suffix = Path(path).suffix.casefold()
            if suffix == ".py":
                argv = ("python", "-m", "py_compile", path)
                command_id = "builtin-python-parse"
            elif suffix in {".js", ".jsx", ".mjs", ".cjs"}:
                argv = ("node", "--check", path)
                command_id = "builtin-node-parse"
            else:
                continue
            checks.append(
                self._make_check(
                    command_id=command_id,
                    kind=VerificationCheckKind.PARSE,
                    stage=VerificationStage.STRUCTURAL,
                    argv=argv,
                    cwd=".",
                    profile_digest=profile.profile_digest,
                    source="trusted-runtime-heuristic",
                    target_paths=(path,),
                    target_symbols=impact.changed_symbols,
                    reason_codes=("changed-file-parse",),
                    required=True,
                    cost=VerificationCost.CHEAP,
                )
            )
        return checks

    def _from_spec(
        self,
        spec: VerificationCommandSpec,
        *,
        stage: VerificationStage,
        profile_digest: str,
        target_paths: tuple[str, ...],
        required: bool,
        reason_codes: tuple[str, ...],
        cost: VerificationCost,
        target_symbols: tuple[str, ...] = (),
    ) -> VerificationCheck:
        argv = _target_argv(spec, target_paths)
        scoped_targets = tuple(path for path in target_paths if _under_cwd(path, spec.cwd))
        return self._make_check(
            command_id=spec.command_id,
            kind=(VerificationCheckKind.TARGETED_TEST if stage is VerificationStage.TARGETED and spec.kind in {VerificationCheckKind.PACKAGE_TEST, VerificationCheckKind.TARGETED_TEST} else spec.kind),
            stage=stage,
            argv=argv,
            cwd=spec.cwd,
            profile_digest=profile_digest,
            source=f"profile:{spec.provenance}",
            target_paths=scoped_targets,
            target_symbols=target_symbols,
            reason_codes=reason_codes,
            required=required,
            cost=cost,
        )

    @staticmethod
    def _make_check(
        *,
        command_id: str,
        kind: VerificationCheckKind,
        stage: VerificationStage,
        argv: tuple[str, ...],
        cwd: str,
        profile_digest: str,
        source: str,
        target_paths: tuple[str, ...],
        target_symbols: tuple[str, ...],
        reason_codes: tuple[str, ...],
        required: bool,
        cost: VerificationCost,
    ) -> VerificationCheck:
        semantic = {
            "command_id": command_id,
            "kind": kind.value,
            "stage": int(stage),
            "argv": argv,
            "cwd": cwd,
            "profile_digest": profile_digest,
            "target_paths": target_paths,
            "target_symbols": target_symbols,
            "reason_codes": reason_codes,
        }
        check_id = f"m83-check-{canonical_digest(semantic)[:24]}"
        return VerificationCheck(
            check_id=check_id,
            kind=kind,
            stage=stage,
            argv=argv,
            cwd=cwd,
            command_id=command_id,
            profile_digest=profile_digest,
            source=source,
            target_paths=target_paths,
            target_symbols=target_symbols,
            reason_codes=reason_codes,
            required=required,
            cost=cost,
        )

    @staticmethod
    def _language_matches(
        spec: VerificationCommandSpec,
        impact: EditImpact,
        profile: VerificationProfile,
    ) -> bool:
        if impact.uncertainty:
            # A partial/unknown impact must widen to every language represented
            # by the trusted profile; restricting to the changed suffix would
            # turn missing intelligence into a false sense of coverage.
            return spec.language in profile.languages or spec.language in {"repository", "generic"}
        if not impact.languages:
            return spec.language in profile.languages or spec.language in {"repository", "generic"}
        return spec.language in impact.languages

    @staticmethod
    def _risk(impact: EditImpact) -> VerificationRisk:
        if impact.is_docs_only:
            return VerificationRisk.LOW
        if (
            impact.uncertainty
            or impact.public_api_changed
            or impact.build_config_paths
            or impact.config_paths
            or _security_sensitive(impact)
            or len(impact.changed_paths) > 8
            or len(impact.languages) > 1
        ):
            return VerificationRisk.HIGH
        return VerificationRisk.MEDIUM

    @staticmethod
    def _reasons(
        impact: EditImpact,
        profile: VerificationProfile,
        risk: VerificationRisk,
    ) -> tuple[VerificationReason, ...]:
        reasons: list[VerificationReason] = []
        if impact.is_docs_only:
            reasons.append(VerificationReason("docs-only", "Documentation-only changes do not select executable checks."))
        if impact.is_test_only:
            reasons.append(VerificationReason("test-only", "Test changes select related tests before broader checks."))
        if impact.changed_paths:
            reasons.append(VerificationReason("direct-edit", "Checks are grounded in the applied edit paths.", impact.changed_paths))
        if impact.changed_symbols:
            reasons.append(VerificationReason("changed-symbols", "Semantic symbol impact was returned by repository intelligence."))
        if impact.related_tests:
            reasons.append(VerificationReason("related-tests", "Repository intelligence associated tests with the changed scope.", impact.related_tests))
        if impact.uncertainty:
            reasons.append(VerificationReason("impact-uncertainty", "Uncertain impact expands verification scope.", impact.changed_paths))
        if _security_sensitive(impact):
            reasons.append(
                VerificationReason(
                    "security-sensitive-impact",
                    "Security-sensitive paths require broader trusted checks.",
                    impact.changed_paths,
                )
            )
        if profile.diagnostics:
            reasons.append(VerificationReason("profile-diagnostic", "Profile discovery reported bounded diagnostics."))
        reasons.append(VerificationReason(f"risk-{risk.value}", f"Planner risk is {risk.value}."))
        return tuple(reasons)

    @staticmethod
    def _deduplicate(checks: list[VerificationCheck]) -> list[VerificationCheck]:
        unique: dict[tuple[object, ...], VerificationCheck] = {}
        for check in checks:
            # The executable contract, rather than a profile-local label, is
            # the identity used for deduplication.  Two trusted manifests may
            # name the same argv differently; scheduling it twice would waste
            # the bounded verification budget without adding evidence.
            key = (check.kind.value, int(check.stage), check.argv, check.cwd)
            previous = unique.get(key)
            if previous is None or (check.required and not previous.required):
                unique[key] = check
        return list(unique.values())

    @staticmethod
    def _prioritize(checks: list[VerificationCheck]) -> list[VerificationCheck]:
        return sorted(checks, key=_check_sort_key)

    def _fit_time_budget(self, checks: list[VerificationCheck]) -> list[VerificationCheck]:
        if not checks:
            return checks
        # ``VerificationCheck.timeout_seconds`` has a 100 ms lower bound.  A
        # tiny total budget must therefore reduce the number of scheduled
        # checks before assigning per-check timeouts; otherwise the returned
        # plan would claim a total bound it cannot satisfy.
        max_budgeted_checks = max(
            1,
            math.floor(self.limits.max_total_seconds / 0.1 + 1e-9),
        )
        if len(checks) > max_budgeted_checks:
            checks = self._prioritize(checks)[:max_budgeted_checks]
        per_check = min(
            self.limits.max_check_timeout,
            self.limits.max_total_seconds / len(checks),
        )
        return [replace(check, timeout_seconds=max(0.1, per_check)) for check in checks]


def _check_sort_key(check: VerificationCheck) -> tuple[object, ...]:
    cost = {VerificationCost.CHEAP: 0, VerificationCost.NORMAL: 1, VerificationCost.EXPENSIVE: 2}[check.cost]
    return (int(check.stage), cost, check.kind.value, check.cwd, check.argv, check.check_id)


def _looks_like_test(path: str) -> bool:
    name = Path(path).name.casefold()
    return (
        "/test/" in f"/{path.casefold()}/"
        or "/tests/" in f"/{path.casefold()}/"
        or name.startswith("test_")
        or name.endswith(("_test.py", "_test.go", "_test.rs"))
        or ".test." in name
        or ".spec." in name
    )


def _security_sensitive(impact: EditImpact) -> bool:
    """Conservatively widen changes in common control-plane boundaries."""
    return any(
        part.casefold() in _SECURITY_PATH_PARTS
        for path in impact.changed_paths
        for part in PurePosixPath(path).parts
    )


def _under_cwd(path: str, cwd: str) -> bool:
    return cwd == "." or path == cwd or path.startswith(cwd.rstrip("/") + "/")


def _relative_to_cwd(path: str, cwd: str) -> str:
    if cwd == ".":
        return path
    if path == cwd:
        return Path(path).name
    prefix = cwd.rstrip("/") + "/"
    return path.removeprefix(prefix)


def _target_argv(spec: VerificationCommandSpec, target_paths: tuple[str, ...]) -> tuple[str, ...]:
    if not target_paths:
        return spec.argv
    scoped = tuple(_relative_to_cwd(path, spec.cwd) for path in target_paths if _under_cwd(path, spec.cwd))
    if not scoped:
        return spec.argv
    argv = spec.argv
    if spec.language == "go" and len(argv) >= 3 and argv[0] == "go" and argv[1] in {"test", "vet"}:
        packages = tuple(sorted({"./" + str(PurePosixPath(path).parent) if str(PurePosixPath(path).parent) not in {"", "."} else "." for path in scoped}))
        return (argv[0], argv[1], *packages)
    if argv[:2] == ("npm", "run"):
        return (*argv, "--", *scoped)
    if argv[-1:] == (".",):
        return (*argv[:-1], *scoped)
    if spec.scope == "file":
        return (*argv, *scoped)
    if spec.kind in {VerificationCheckKind.PACKAGE_TEST, VerificationCheckKind.TARGETED_TEST, VerificationCheckKind.LINT, VerificationCheckKind.FORMAT, VerificationCheckKind.TYPECHECK}:
        return (*argv, *scoped)
    return argv


def _unique_reasons(reasons: tuple[VerificationReason, ...]) -> tuple[VerificationReason, ...]:
    unique: dict[tuple[str, str, tuple[str, ...]], VerificationReason] = {}
    for reason in reasons:
        unique[(reason.code, reason.message, reason.paths)] = reason
    return tuple(sorted(unique.values(), key=lambda item: (item.code, item.message, item.paths)))


__all__ = ["AutonomousPlannerLimits", "AutonomousVerificationPlanner", "VerificationPlanner"]
