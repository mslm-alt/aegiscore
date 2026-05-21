from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class GuardedActionRequest:
    action_id: str
    action_type: str
    target: str
    target_type: str
    actor: str
    reason: str
    confirmation_phrase: str
    required_confirmation_phrase: str
    dry_run_required: bool
    dry_run_completed: bool
    role_required: str
    current_role: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GuardedActionResult:
    status: str
    action_type: str
    target: str
    message: str
    would_do: List[str] = field(default_factory=list)
    required_guards: List[str] = field(default_factory=list)
    missing_guards: List[str] = field(default_factory=list)
    audit_required: bool = True
    execution_enabled: bool = False
    error: str | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionGuardPolicy:
    action_type: str
    enabled: bool
    phase: str
    role_required: str
    dry_run_required: bool
    typed_confirmation_required: bool
    reason_required: bool
    audit_required: bool
    allowed_in_phase_2: bool
    destructive: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
