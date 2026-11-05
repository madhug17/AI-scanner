from typing import Type
from scanner.rules.base import SecurityRule

# Import all rules
from scanner.rules.authentication.rules import (
    AuthenticationRule,
    RateLimitingRule,
    JwtSecurityRule,
    CookieSecurityRule,
    PasswordHashingRule,
    AccountEnumerationRule,
    PasswordResetTokenRule,
)
from scanner.rules.authorization.rules import (
    AuthorizationRule,
    IdorBolaRule,
    AdminProtectionRule,
)
from scanner.rules.injection.rules import (
    SqlInjectionRule,
    CommandInjectionRule,
    XssRule,
    PathTraversalRule,
    SsrfRule,
    NosqlInjectionRule,
    UnsafeDeserializationRule,
)
from scanner.rules.secrets.rules import (
    HardcodedSecretRule,
    DefaultCredentialsRule,
    GitHistoryLeakRule,
    CicdSecretRule,
    FrontendSecretRule,
)
from scanner.rules.configuration.rules import (
    HttpsEnforcementRule,
    FileUploadSafetyRule,
    CorsRule,
    DebugExposureRule,
    SecurityHeadersRule,
    CsrfProtectionRule,
    DatabaseExposureRule,
    CloudStorageRule,
    ContainerInfraRule,
)
from scanner.rules.dependencies.rules import (
    DependencyVulnerabilitiesRule,
    SuspiciousPackagesRule,
)
from scanner.rules.api_security.rules import (
    MassAssignmentRule,
    InputValidationRule,
    ExcessiveDataExposureRule,
    ErrorHandlingRule,
    LoggingHygieneRule,
    PaginationRule,
    WebhookVerificationRule,
    PaymentTamperingRule,
)
from scanner.rules.ai_security.rules import (
    AiSecurityRule,
    PromptInjectionRule,
    InsecureOutputHandlingRule,
    ExcessiveAgencyRule,
    SystemPromptLeakageRule,
    LlmCostAbuseRule,
    RagDataIsolationRule,
    LlmApiKeyExposureRule,
    PiiToLlmRule,
    UnsafeModelLoadingRule,
    ToolMcpPermissionsRule,
)


ALL_RULE_CLASSES: list[Type[SecurityRule]] = [
    # A. Authentication and Authorization
    AuthenticationRule,          # SEC-001
    AuthorizationRule,           # SEC-002
    IdorBolaRule,                # SEC-003
    RateLimitingRule,            # SEC-004
    HttpsEnforcementRule,        # SEC-005
    HardcodedSecretRule,         # SEC-006
    JwtSecurityRule,             # SEC-007
    SqlInjectionRule,            # SEC-008
    AdminProtectionRule,         # SEC-009
    AiSecurityRule,              # SEC-010

    # B. Application Security
    CookieSecurityRule,          # SEC-011
    PasswordHashingRule,         # SEC-012
    MassAssignmentRule,          # SEC-013
    AccountEnumerationRule,      # SEC-014
    PasswordResetTokenRule,      # SEC-015
    DefaultCredentialsRule,      # SEC-016
    InputValidationRule,         # SEC-017
    CommandInjectionRule,        # SEC-018
    XssRule,                     # SEC-019
    PathTraversalRule,           # SEC-020
    SsrfRule,                    # SEC-021
    NosqlInjectionRule,          # SEC-022
    FileUploadSafetyRule,        # SEC-023
    UnsafeDeserializationRule,   # SEC-024

    # C. Configuration & Infrastructure
    CorsRule,                    # SEC-025
    DebugExposureRule,           # SEC-026
    SecurityHeadersRule,         # SEC-027
    CsrfProtectionRule,          # SEC-028
    DatabaseExposureRule,        # SEC-029
    CloudStorageRule,            # SEC-030
    ContainerInfraRule,          # SEC-031
    DependencyVulnerabilitiesRule, # SEC-032
    SuspiciousPackagesRule,      # SEC-033
    GitHistoryLeakRule,          # SEC-034
    CicdSecretRule,              # SEC-035

    # D. Data Protection & API Security
    ExcessiveDataExposureRule,   # SEC-036
    ErrorHandlingRule,           # SEC-037
    LoggingHygieneRule,          # SEC-038
    PaginationRule,              # SEC-039
    WebhookVerificationRule,     # SEC-040
    PaymentTamperingRule,        # SEC-041
    FrontendSecretRule,          # SEC-042

    # E. AI and LLM Security
    PromptInjectionRule,         # SEC-043
    InsecureOutputHandlingRule,  # SEC-044
    ExcessiveAgencyRule,         # SEC-045
    SystemPromptLeakageRule,     # SEC-046
    LlmCostAbuseRule,            # SEC-047
    RagDataIsolationRule,        # SEC-048
    LlmApiKeyExposureRule,       # SEC-049
    PiiToLlmRule,                # SEC-050
    UnsafeModelLoadingRule,      # SEC-051
    ToolMcpPermissionsRule,      # SEC-052
]


class RuleRegistry:
    def __init__(self, rule_classes: list[Type[SecurityRule]] | None = None):
        self._rules: dict[str, SecurityRule] = {}
        classes = rule_classes if rule_classes is not None else ALL_RULE_CLASSES
        for cls in classes:
            rule_instance = cls()
            self._rules[rule_instance.rule_id] = rule_instance

    def get_all_rules(self) -> list[SecurityRule]:
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        return self._rules.get(rule_id)

    def get_rules_by_category(self, category: str) -> list[SecurityRule]:
        return [r for r in self._rules.values() if r.category.lower() == category.lower()]

    def count(self) -> int:
        return len(self._rules)


default_registry = RuleRegistry()

