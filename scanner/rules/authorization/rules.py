import ast
import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class AuthorizationRule(SecurityRule):
    """SEC-002: Detects resource access without recognizable permission checks."""
    rule_id = "SEC-002"
    title = "Potential missing authorization check"
    category = "Authorization"
    severity = Severity.HIGH
    default_status = FindingStatus.NEEDS_VERIFICATION
    description = "Route appears to access a user-scoped database resource without verifying user ownership or role."
    impact = "An authenticated user might access, modify, or delete resources belonging to another user."
    recommendation = "Verify that the authenticated user owns or has explicit permission to access the requested resource."

    ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}
    RESOURCE_KEYWORDS = {"user", "order", "account", "profile", "payment", "invoice", "document", "customer", "booking", "record"}
    OWNERSHIP_KEYWORDS = {"owner_id", "user_id", "created_by", "account_id", "tenant_id", "current_user", "request.user", "organization_id", "has_permission", "is_admin"}

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
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route = None
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr.lower() in self.ROUTE_METHODS:
                        route = decorator
                        break

            if route is None:
                continue

            route_path = ""
            if route.args and isinstance(route.args[0], ast.Constant):
                route_path = str(route.args[0].value).lower()

            func_source = ast.get_source_segment(content, node) or ""
            source_lower = func_source.lower()

            has_resource = any(kw in route_path or kw in source_lower for kw in self.RESOURCE_KEYWORDS)
            has_db_access = any(kw in source_lower for kw in (".query(", ".filter(", ".get(", ".execute(", ".first(", ".one("))

            if not has_resource or not has_db_access:
                continue

            has_ownership_check = any(kw in source_lower for kw in self.OWNERSHIP_KEYWORDS)
            if has_ownership_check:
                continue

            line_no = route.lineno
            findings.append(
                self.create_finding(
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else node.name,
                    description=f"Endpoint '{node.name}' queries database resource '{route_path}' without apparent user ownership filtering.",
                )
            )

        return findings


class IdorBolaRule(SecurityRule):
    """SEC-003: Identifies Insecure Direct Object Reference (IDOR / BOLA)."""
    rule_id = "SEC-003"
    title = "Potential IDOR / Broken Object Level Authorization"
    category = "Authorization"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Endpoint takes an object/record ID parameter directly into a query without scoping to current user/organization."
    impact = "Attackers can manipulate the ID in the request to read or alter other users' private objects."
    recommendation = "Scope database queries by current_user.id or tenant_id (e.g. query.filter_by(id=obj_id, user_id=current_user.id))."

    ID_PARAM_PATTERN = re.compile(r"\{([a-zA-Z0-9_]*(id|pk|uuid))\}", re.IGNORECASE)

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
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_path = None
            route_line = node.lineno
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr.lower() in {"get", "put", "delete", "patch"}:
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            route_path = str(decorator.args[0].value)
                            route_line = decorator.lineno
                            break

            if not route_path or not self.ID_PARAM_PATTERN.search(route_path):
                continue

            func_source = ast.get_source_segment(content, node) or ""
            source_lower = func_source.lower()

            # If it filters by user_id or owner_id or verifies permission, it's safe
            if any(k in source_lower for k in ["user_id", "owner_id", "tenant_id", "current_user", "check_object_permissions"]):
                continue

            # If it executes a lookup by ID directly
            if any(k in source_lower for k in [".get(", "filter(", "filter_by("]):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=route_line,
                        line_end=route_line,
                        code_snippet=lines[route_line - 1].strip() if route_line <= len(lines) else route_path,
                        description=f"Route '{route_path}' references object ID directly in query without verifying user ownership or tenant context.",
                    )
                )

        return findings


class AdminProtectionRule(SecurityRule):
    """SEC-009: Detects exposed administrative endpoints lacking admin-role checks."""
    rule_id = "SEC-009"
    title = "Exposed administrative route without role enforcement"
    category = "Authorization"
    severity = Severity.HIGH
    default_status = FindingStatus.NEEDS_VERIFICATION
    description = "Route path starts with or contains '/admin/' but does not enforce administrative privileges."
    impact = "Non-admin or anonymous users may access privileged management endpoints."
    recommendation = "Enforce admin role verification (e.g. Depends(require_admin) or @role_required('admin'))."

    ADMIN_KEYWORDS = {"admin", "superuser", "role_admin", "require_admin", "is_admin"}

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
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_admin_route = False
            route_line = node.lineno
            path_str = ""

            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.args and isinstance(decorator.args[0], ast.Constant):
                        path_str = str(decorator.args[0].value).lower()
                        if "/admin" in path_str:
                            is_admin_route = True
                            route_line = decorator.lineno
                            break

            if not is_admin_route:
                continue

            func_source = ast.get_source_segment(content, node) or ""
            source_lower = func_source.lower()

            has_admin_check = any(k in source_lower for k in self.ADMIN_KEYWORDS)
            if not has_admin_check:
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=route_line,
                        line_end=route_line,
                        code_snippet=lines[route_line - 1].strip() if route_line <= len(lines) else path_str,
                        description=f"Admin endpoint '{path_str}' lacks explicit administrator permission checks.",
                    )
                )

        return findings

