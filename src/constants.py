from enum import Enum
from typing import Self


class CVSSSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown severity value {raw_value}")
            return None


class UserInteraction(str, Enum):
    REQUIRED = "required"
    NONE = "none"
    ACTIVE = "active"
    PASSIVE = "passive"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown User Interaction value {raw_value}")
            return None


class AvailabilityImpact(str, Enum):
    NONE = "none"
    PARTIAL = "partial"
    HIGH = "high"
    LOW = "low"
    COMPLETE = "complete"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Availibility Impact value {raw_value}")
            return None


class AttackVector(str, Enum):
    NETWORK = "network"
    ADJACENT = "adjacent_network"
    LOCAL = "local"
    PHYSICAL = "physical"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Availibility Impact value {raw_value}")
            return None


class PrivilegesRequired(str, Enum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Availibility Impact value {raw_value}")
            return None


class AttackComplexity(str, Enum):
    HIGH = ("high",)
    LOW = ("low",)

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Attack complexity value {raw_value}")
            return None
