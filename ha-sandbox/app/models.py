from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComponentType(str, Enum):
    INTEGRATION = "integration"
    CARD = "card"  # lovelace / frontend
    THEME = "theme"
    PYTHON_SCRIPT = "python_script"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    SCANNING = "scanning"
    AI_REVIEW = "ai_review"
    DONE = "done"
    FAILED = "failed"


class Finding(BaseModel):
    severity: Severity
    category: str  # e.g. "network", "code_injection", "data_exfiltration"
    file: str
    line: int | None = None
    code: str = ""
    description: str


class ManifestInfo(BaseModel):
    domain: str = ""
    name: str = ""
    version: str = ""
    documentation: str = ""
    dependencies: list[str] = []
    requirements: list[str] = []
    iot_class: str = ""
    component_type: ComponentType = ComponentType.UNKNOWN


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: "")
    repo_url: str
    name: str = ""
    status: ScanStatus = ScanStatus.QUEUED
    created_at: datetime = Field(default_factory=datetime.now)
    manifest: ManifestInfo | None = None
    findings: list[Finding] = []
    ai_summary: str = ""
    ai_score: float | None = None  # 0-10, 10 = safe
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def score_label(self) -> str:
        if self.ai_score is None:
            return "N/A"
        if self.ai_score >= 8:
            return "SAFE"
        if self.ai_score >= 5:
            return "CAUTION"
        return "DANGER"
