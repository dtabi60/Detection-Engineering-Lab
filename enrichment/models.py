from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class TIResult:
    source: str
    status: str
    verdict: str
    confidence: int
    summary: str
    details: Dict[str, Any]

    def to_dict(self) -> dict:
        return asdict(self)


def unknown_result(source: str, summary: str = "No result available.") -> dict:
    return TIResult(
        source=source,
        status="unknown",
        verdict="unknown",
        confidence=0,
        summary=summary,
        details={}
    ).to_dict()


def error_result(source: str, error: str) -> dict:
    return TIResult(
        source=source,
        status="error",
        verdict="unknown",
        confidence=0,
        summary=f"{source} lookup failed.",
        details={"error": error}
    ).to_dict()