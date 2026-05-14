from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ScanTarget:
    url: str
    auth_headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScannerFinding:
    title: str
    severity: str
    description: str | None = None
    url: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    request: dict[str, Any] | str | None = None
    response: dict[str, Any] | str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ScannerPlugin(ABC):
    name: str

    @abstractmethod
    def start_scan(self, target: ScanTarget) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_status(self, scanner_scan_id: str) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_findings(self, scanner_scan_id: str) -> list[ScannerFinding]:
        raise NotImplementedError
