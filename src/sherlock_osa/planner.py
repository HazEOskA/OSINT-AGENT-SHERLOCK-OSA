from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class PlannerDecision:
    source: str
    run: bool
    reason: str
    priority: int

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "run": self.run,
            "reason": self.reason,
            "priority": self.priority,
        }


class AdaptiveSourcePlanner:
    """Truth-aware source selection.

    Planning proves only that a source is runnable. It never marks the source as
    truthful or FOUND. Runtime adapters and canaries own presence verification.
    """

    _priority_ceiling = {
        "QUICK": 22,
        "DEEP": 40,
        "MAX": 100,
    }

    def __init__(self, mode: str = "DEEP") -> None:
        normalized = str(mode).strip().upper()
        if normalized not in self._priority_ceiling:
            raise ValueError(f"unsupported planner mode: {mode}")
        self.mode = normalized

    def plan(self, modules: Sequence[object], identifier: object) -> tuple[tuple[object, ...], tuple[PlannerDecision, ...]]:
        runnable: list[tuple[int, str, object]] = []
        decisions: list[PlannerDecision] = []
        depth = int(getattr(identifier, "depth", 0))

        for module in modules:
            descriptor = getattr(module, "descriptor", None)
            name = str(getattr(module, "name", "unknown"))

            if descriptor is None:
                runnable.append((0, name, module))
                decisions.append(PlannerDecision(name, True, "LOCAL_OR_UNDESCRIBED_SOURCE", 0))
                continue

            priority = int(getattr(descriptor, "priority", 50))
            max_depth = int(getattr(descriptor, "max_identifier_depth", 0))

            if depth > max_depth:
                decisions.append(PlannerDecision(name, False, "SOURCE_DEPTH_BOUND", priority))
                continue

            dependency_health = getattr(descriptor, "dependency_health", None)
            if callable(dependency_health):
                available, _version, version_match = dependency_health()
                if not available:
                    decisions.append(PlannerDecision(name, False, "DEPENDENCY_UNAVAILABLE", priority))
                    continue
                if not version_match:
                    decisions.append(PlannerDecision(name, False, "DEPENDENCY_VERSION_DRIFT", priority))
                    continue

            requires_key = bool(getattr(descriptor, "requires_key", False))
            credential_env = getattr(descriptor, "credential_env", None)
            if requires_key and (
                not credential_env or not os.getenv(str(credential_env), "").strip()
            ):
                decisions.append(PlannerDecision(name, False, "MISSING_CREDENTIAL", priority))
                continue

            ceiling = self._priority_ceiling[self.mode]
            if priority > ceiling:
                decisions.append(PlannerDecision(name, False, f"MODE_{self.mode}_PRIORITY_CEILING", priority))
                continue

            if self.mode == "QUICK" and bool(getattr(descriptor, "historical", False)):
                decisions.append(PlannerDecision(name, False, "QUICK_SKIPS_HISTORICAL", priority))
                continue

            runnable.append((priority, name, module))
            decisions.append(PlannerDecision(name, True, "PLANNED_RUNTIME_TRUTH_REQUIRED", priority))

        runnable.sort(key=lambda item: (item[0], item[1]))
        return tuple(item[2] for item in runnable), tuple(decisions)

    def describe(self) -> Mapping[str, object]:
        return {
            "mode": self.mode,
            "priority_ceiling": self._priority_ceiling[self.mode],
            "strategy": "IDENTIFIER_DEPTH_PRIORITY_DEPENDENCY_CREDENTIAL_TRUTH_AWARE",
            "planning_is_truth_verification": False,
            "runtime_truth_required": True,
        }
