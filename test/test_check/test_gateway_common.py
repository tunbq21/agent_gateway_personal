"""Shared baseline verification tests for Gateway configuration and CEL rules (14 Test Cases)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import yaml  # noqa: E402
from start_local_gateway import evaluate_cel_expr  # noqa: E402


class TestGatewaySharedChecks(unittest.TestCase):
    """14 shared smoke & hardening tests tracked in Git (safe for CI & Post-Deploy Prod)."""

    local_cfg: dict = {}
    enterprise_cfg: dict = {}
    mcp_policies: dict = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.local_cfg = yaml.safe_load((ROOT_DIR / "config.yaml").read_text(encoding="utf-8"))
        cls.enterprise_cfg = yaml.safe_load((ROOT_DIR / "config.enterprise.yaml").read_text(encoding="utf-8"))
        cls.mcp_policies = (cls.enterprise_cfg.get("mcp") or {}).get("policies") or {}

    def test_01_config_yaml_syntax_and_root_mapping(self) -> None:
        """SEC-CFG-01: Verify config.yaml and config.enterprise.yaml parse as valid YAML mappings."""
        self.assertIsInstance(self.local_cfg, dict)
        self.assertIsInstance(self.enterprise_cfg, dict)
        self.assertIn("mcp", self.local_cfg)
        self.assertIn("mcp", self.enterprise_cfg)

    def test_02_enterprise_config_api_key_strict_mode(self) -> None:
        """SEC-CFG-02: Verify enterprise config sets LLM API key enforcement to strict."""
        api_key_policy = (self.enterprise_cfg.get("llm") or {}).get("policies", {}).get("apiKey", {})
        self.assertEqual(api_key_policy.get("mode"), "strict")

    def test_03_enterprise_config_no_hardcoded_secret_keys(self) -> None:
        """SEC-CFG-03: Ensure no hardcoded OpenAI or static agw_sk_ keys exist in config.enterprise.yaml."""
        llm_cfg = self.enterprise_cfg.get("llm") or {}
        for prov in llm_cfg.get("providers") or []:
            api_key_val = str((prov.get("params") or {}).get("apiKey", ""))
            self.assertFalse(api_key_val.startswith("sk-"), "Hardcoded OpenAI key must not exist")
        for key_entry in (llm_cfg.get("policies", {}).get("apiKey", {}).get("keys") or []):
            key_val = str(key_entry.get("key", ""))
            self.assertFalse(key_val.startswith("agw_sk_"), "Static agw_sk_ key must be replaced with $ENV_VAR")

    def test_04_enterprise_config_jwt_auth_enabled(self) -> None:
        """SEC-CFG-04: Verify jwtAuth is enabled with issuer, audiences, and JWKS URL."""
        jwt_auth = self.mcp_policies.get("jwtAuth") or {}
        self.assertTrue(jwt_auth.get("issuer"), "jwtAuth.issuer must be configured")
        self.assertTrue(jwt_auth.get("audiences"), "jwtAuth.audiences must be configured")
        self.assertTrue((jwt_auth.get("jwks") or {}).get("url"), "jwtAuth.jwks.url must be configured")

    def test_05_enterprise_config_has_mcp_authorization_rules(self) -> None:
        """SEC-CFG-05: Ensure mcpAuthorization.rules is non-empty in enterprise config."""
        rules = (self.mcp_policies.get("mcpAuthorization") or {}).get("rules") or []
        self.assertGreater(len(rules), 0, "mcpAuthorization.rules must not be empty")

    def test_06_enterprise_config_has_rate_limit_protection(self) -> None:
        """SEC-CFG-06: Ensure localRateLimit is configured with positive maxTokens."""
        rate_limit = self.mcp_policies.get("localRateLimit") or []
        self.assertGreater(len(rate_limit), 0, "localRateLimit must be configured")
        self.assertGreater(rate_limit[0].get("maxTokens", 0), 0)

    def test_07_enterprise_config_cors_restricted_and_exposes_session(self) -> None:
        """SEC-CFG-07: Verify CORS restricts wildcard origins and exposes Mcp-Session-Id."""
        cors = self.mcp_policies.get("cors") or {}
        origins = cors.get("allowOrigins") or []
        expose = cors.get("exposeHeaders") or []
        self.assertNotIn("*", origins, "Production CORS allowOrigins must not use wildcard '*'")
        self.assertIn("Mcp-Session-Id", expose)

    def test_08_enterprise_config_ui_oidc_enabled(self) -> None:
        """SEC-CFG-08: Verify ui.policies.oidc is configured to protect Admin UI."""
        oidc = ((self.enterprise_cfg.get("ui") or {}).get("policies") or {}).get("oidc") or {}
        self.assertTrue(oidc.get("issuer"), "ui.policies.oidc.issuer must be configured")
        self.assertTrue(oidc.get("clientId"), "ui.policies.oidc.clientId must be configured")
        self.assertEqual(oidc.get("clientSecret"), "$UI_OIDC_CLIENT_SECRET")

    def test_09_cel_smoke_allow_matching_tenant(self) -> None:
        """SEC-CFG-09: Allow tool invocation when JWT tenant_id matches tool argument tenant_id."""
        expr = (
            'mcp.tool.name == "get_record" && '
            "has(mcp.tool.arguments.tenant_id) && "
            "mcp.tool.arguments.tenant_id == jwt.tenant_id"
        )
        ctx = {
            "jwt": {"sub": "user-101", "tenant_id": "101"},
            "mcp": {"tool": {"name": "get_record", "arguments": {"tenant_id": "101"}}},
        }
        self.assertTrue(evaluate_cel_expr(expr, ctx))

    def test_10_cel_smoke_block_mismatched_tenant(self) -> None:
        """SEC-CFG-10: Block cross-tenant access when tool argument tenant_id differs from JWT claim."""
        expr = (
            'mcp.tool.name == "get_record" && '
            "has(mcp.tool.arguments.tenant_id) && "
            "mcp.tool.arguments.tenant_id == jwt.tenant_id"
        )
        ctx = {
            "jwt": {"sub": "user-101", "tenant_id": "101"},
            "mcp": {"tool": {"name": "get_record", "arguments": {"tenant_id": "999"}}},
        }
        self.assertFalse(evaluate_cel_expr(expr, ctx))

    def test_11_cel_smoke_block_missing_tenant_field(self) -> None:
        """SEC-CFG-11: Block tool invocation when tenant_id argument is omitted."""
        expr = 'mcp.tool.name == "get_record" && has(mcp.tool.arguments.tenant_id) && mcp.tool.arguments.tenant_id == jwt.tenant_id'
        ctx = {
            "jwt": {"sub": "user-101", "tenant_id": "101"},
            "mcp": {"tool": {"name": "get_record", "arguments": {}}},
        }
        self.assertFalse(evaluate_cel_expr(expr, ctx))

    def test_12_cel_smoke_tool_allowlist_enforcement(self) -> None:
        """SEC-CFG-12: Only allowlisted tool names evaluate to true."""
        expr = 'mcp.tool.name in ["list_resources", "get_metadata"]'
        self.assertTrue(evaluate_cel_expr(expr, {"mcp": {"tool": {"name": "list_resources"}}}))
        self.assertFalse(evaluate_cel_expr(expr, {"mcp": {"tool": {"name": "drop_database"}}}))

    def test_13_cel_smoke_block_sensitive_system_table_case_insensitive(self) -> None:
        """SEC-CFG-13: Block run_query targeting system.users regardless of casing."""
        expr = 'mcp.tool.name == "run_query" && !mcp.tool.arguments.query.lowerAscii().contains("system.users")'
        for query in ("SELECT * FROM system.users", "SELECT * FROM SYSTEM.USERS"):
            ctx = {"jwt": {"sub": "user-101"}, "mcp": {"tool": {"name": "run_query", "arguments": {"query": query}}}}
            self.assertFalse(evaluate_cel_expr(expr, ctx))
        allowed_ctx = {
            "jwt": {"sub": "user-101"},
            "mcp": {"tool": {"name": "run_query", "arguments": {"query": "SELECT count() FROM orders"}}},
        }
        self.assertTrue(evaluate_cel_expr(expr, allowed_ctx))

    def test_14_cel_smoke_admin_role_override(self) -> None:
        """SEC-CFG-14: Allow admin role override in combined policy."""
        expr = 'jwt.role == "admin" || (mcp.tool.name == "get_record" && mcp.tool.arguments.tenant_id == jwt.tenant_id)'
        admin_ctx = {
            "jwt": {"sub": "admin-1", "role": "admin"},
            "mcp": {"tool": {"name": "get_record", "arguments": {"tenant_id": "any"}}},
        }
        self.assertTrue(evaluate_cel_expr(expr, admin_ctx))


if __name__ == "__main__":
    unittest.main()
