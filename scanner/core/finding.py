from enum import Enum
from pydantic import BaseModel,Field
class Severity(str,Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
class FindingStatus(str,Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NEEDS_VERIFICATION = "needs_verification"
    NOT_DETECTED = "not_detected"
class Evidence(str,Enum):
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
