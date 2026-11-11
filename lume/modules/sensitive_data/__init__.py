"""Sensitive data module initializing and registering OWASP LLM02 rules."""

from lume.core.rule_loader.base import RuleRegistry
from lume.modules.sensitive_data.rules.sd_001_credential_probing import CredentialProbingRule
from lume.modules.sensitive_data.rules.sd_002_pii_harvesting import PIIHarvestingRule


def register_rules() -> None:
    """Register OWASP LLM02 sensitive data rules into the global RuleRegistry."""
    rules = [
        CredentialProbingRule(),
        PIIHarvestingRule(),
    ]
    for rule in rules:
        RuleRegistry.register(rule)


# Auto-register upon import
register_rules()

__all__ = [
    "register_rules",
    "CredentialProbingRule",
    "PIIHarvestingRule",
]

