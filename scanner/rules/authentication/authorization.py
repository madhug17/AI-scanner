
import ast

from scanner.core.finding import (
    Finding,
    Evidence,
    Severity,
    FindingStatus,
)


class AuthorizationRule:

    rule_id = "SEC-002"

    ROUTE_METHODS = {
        "get", "post", "put", "patch", "delete"
    }

    RESOURCE_KEYWORDS = {
        "user", "order", "account", "profile",
        "payment", "invoice", "document",
        "customer", "booking", "record",
    }

    OWNERSHIP_KEYWORDS = {
        "owner_id", "user_id", "created_by",
        "account_id", "tenant_id",
        "current_user", "request.user",
        "organization_id",
    }

    def scan(self, file_path: str, content: str) -> list[Finding]:

        findings = []

        if not file_path.lower().endswith(".py"):
            return findings

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.splitlines()

        for node in ast.walk(tree):

            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue

            route = None

            for decorator in node.decorator_list:

                if not isinstance(decorator, ast.Call):
                    continue

                if not isinstance(decorator.func, ast.Attribute):
                    continue

                if decorator.func.attr.lower() in self.ROUTE_METHODS:
                    route = decorator
                    break

            if route is None:
                continue

            route_path = ""

            if route.args and isinstance(route.args[0], ast.Constant):
                route_path = str(route.args[0].value).lower()

            # Look for resource-related database access
            function_source = ast.get_source_segment(content, node) or ""

            source_lower = function_source.lower()

            has_resource = any(
                keyword in route_path or keyword in source_lower
                for keyword in self.RESOURCE_KEYWORDS
            )

            has_database_access = any(
                keyword in source_lower
                for keyword in (
                    ".query(",
                    ".filter(",
                    ".get(",
                    ".execute(",
                    ".first(",
                    ".one(",
                )
            )

            if not has_resource or not has_database_access:
                continue

            has_ownership_check = any(
                keyword in source_lower
                for keyword in self.OWNERSHIP_KEYWORDS
            )

            if has_ownership_check:
                continue

            line_number = route.lineno

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Potential missing authorization check",
                    category="Authorization",
                    severity=Severity.HIGH,
                    status=FindingStatus.NEEDS_VERIFICATION,
                    description=(
                        "This route appears to access a user-related "
                        "resource without a recognizable ownership or "
                        "permission check."
                    ),
                    impact=(
                        "If access control is missing, one user may "
                        "access or modify another user's resources."
                    ),
                    recommendation=(
                        "Verify that the authenticated user is authorized "
                        "to access the requested resource. Enforce ownership "
                        "and permission checks on the server."
                    ),
                    evidence=[
                        Evidence(
                            file_path=file_path,
                            line_start=line_number,
                            line_end=line_number,
                            code_snippet=lines[line_number - 1].strip(),
                        )
                    ],
                )
            )

        return findings
