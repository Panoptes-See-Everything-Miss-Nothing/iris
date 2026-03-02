from enum import StrEnum
import logging

logger = logging.getLogger(__name__)


# this is factory method which returns a method from last return stmt
def from_raw_factory():
    def from_raw(cls, raw_value: str | None) -> str | None:
        if not raw_value:
            return None
        clean = raw_value.lower().strip()
        try:
            return cls(clean).value
        except ValueError:
            logger.error("Unknown %s value %s", cls.__name__, raw_value)
            return None

    return classmethod(from_raw)


class BaseSeverity(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    # classmethod decorator sends class as first param iternally
    from_raw = from_raw_factory()  # this creats from_raw() for CVSSSeverity class


class UserInteraction(StrEnum):
    required = "required"
    none = "none"
    active = "active"
    passive = "passive"

    from_raw = from_raw_factory()


class AvailabilityImpact(StrEnum):
    none = "none"
    partial = "partial"
    high = "high"
    low = "low"
    complete = "complete"

    from_raw = from_raw_factory()


class AttackVector(StrEnum):
    network = "network"
    adjacent_network = "adjacent_network"
    local = "local"
    physical = "physical"

    from_raw = from_raw_factory()


class PrivilegesRequired(StrEnum):
    none = "none"
    low = "low"
    high = "high"

    from_raw = from_raw_factory()


class AttackComplexity(StrEnum):
    high = "high"
    low = "low"

    from_raw = from_raw_factory()


class IntegrityImpact(StrEnum):
    not_defined = "not_defined"
    none = "none"
    complete = "complete"
    high = "high"
    low = "low"
    partial = "partial"

    from_raw = from_raw_factory()


class ConfidentialityImpact(StrEnum):
    complete = "complete"
    high = "high"
    none = "none"
    not_defined = "not_defined"
    partial = "partial"
    low = "low"

    from_raw = from_raw_factory()


class Authentication(StrEnum):
    single = "single"
    none = "none"
    multiple = "multiple"

    from_raw = from_raw_factory()


class Scope(StrEnum):
    changed = "changed"
    unchanged = "unchanged"

    from_raw = from_raw_factory()


class AccessVector(StrEnum):
    network = "network"
    local = "local"
    adjacent_network = "adjacent_network"

    from_raw = from_raw_factory()


class AccessComplexity(StrEnum):
    low = "low"
    high = "high"
    medium = "medium"

    from_raw = from_raw_factory()
