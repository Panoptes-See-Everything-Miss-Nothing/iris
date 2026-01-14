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
    HIGH = "high"
    LOW = "low"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Attack complexity value {raw_value}")
            return None


class IntegrityImpact(str, Enum):
    NOT_DEFINED = "not_defined"
    NONE = "none"
    COMPLETE = "complete"
    HIGH = "high"
    LOW = "low"
    PARTIAL = "partial"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Integrity Impact value {raw_value}")
            return None


class ConfedentialityImpact(str, Enum):
    COMPLETE = "complete"
    HIGH = "high"
    NONE = "none"
    NOT_DEFINED = "not_defined"
    PARTIAL = "partial"
    LOW = "low"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Confedentiality Impact value {raw_value}")
            return None


class Authentication(str, Enum):
    SINGLE = "single"
    NONE = ("none",)
    MULTIPLE = "multiple"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Authentication value {raw_value}")
            return None


class Scope(str, Enum):
    CHANGED = ("changed",)
    UNCHANGED = "unchanged"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Scope value {raw_value}")
            return None


class AccessVector(str, Enum):
    NETWORK = "network"
    LOCAL = "local"
    ADJACENT_NETWORK = "adjacent_network"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Access Vector value {raw_value}")
            return None


class AccessComplexity(str, Enum):
    LOW = "low"
    HIGH = "high"
    MEDIUM = "medium"

    @classmethod
    def from_raw(cls, raw_value: str | None) -> Self | None:
        if not raw_value:
            return None
        try:
            return cls(raw_value.upper())
        except ValueError:
            print(f"Unknown Access Complexity value {raw_value}")
            return None
