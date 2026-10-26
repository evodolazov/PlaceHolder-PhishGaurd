"""Named, deterministic email heuristics for day 1."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.engines.email.features import EmailFeatures
from src.explainability.reasons import build_evidence

RuleFn = Callable[[EmailFeatures], "EmailRuleResult"]


@dataclass(frozen=True)
class EmailRuleResult:
    """Outcome of a single email heuristic."""

    rule_id: str
    fired: bool
    weight: int
    severity: str
    value: Any
    description: str

    def to_evidence(self) -> dict[str, Any]:
        return build_evidence(
            source="email_rules",
            indicator=self.rule_id,
            severity=self.severity,
            value=self.value,
            description=self.description,
        ).to_dict()


def _result(
    *,
    rule_id: str,
    fired: bool,
    weight: int,
    severity: str,
    value: Any,
    description: str,
) -> EmailRuleResult:
    return EmailRuleResult(
        rule_id=rule_id,
        fired=fired,
        weight=weight if fired else 0,
        severity=severity,
        value=value,
        description=description,
    )


def display_name_domain_mismatch_rule(features: EmailFeatures) -> EmailRuleResult:
    return _result(
        rule_id="email.display_name_domain_mismatch",
        fired=features.display_name_domain_mismatch,
        weight=25,
        severity="high",
        value={
            "display_name": features.from_display_name,
            "brand": features.display_name_brand,
            "from_domain": features.from_registrable_domain,
        },
        description="The sender display name impersonates a brand that does not match the From domain.",
    )


def from_reply_to_mismatch_rule(features: EmailFeatures) -> EmailRuleResult:
    return _result(
        rule_id="email.from_reply_to_mismatch",
        fired=features.from_reply_to_mismatch,
        weight=20,
        severity="medium",
        value={
            "from_domain": features.from_registrable_domain,
            "reply_to_domain": features.reply_to_registrable_domain,
        },
        description="The Reply-To domain does not match the From domain.",
    )


def auth_results_fail_rule(features: EmailFeatures) -> EmailRuleResult:
    return _result(
        rule_id="email.auth_results_fail",
        fired=features.auth_fail,
        weight=25,
        severity="high",
        value={"spf": features.auth_spf, "dkim": features.auth_dkim, "dmarc": features.auth_dmarc},
        description="Authentication-Results reports SPF, DKIM, or DMARC failure.",
    )


def link_text_href_mismatch_rule(features: EmailFeatures) -> EmailRuleResult:
    fired = len(features.mismatched_links) > 0
    return _result(
        rule_id="email.link_text_href_mismatch",
        fired=fired,
        weight=30,
        severity="high",
        value=list(features.mismatched_links),
        description="Visible link text does not match the actual destination URL.",
    )


def urgency_language_rule(features: EmailFeatures) -> EmailRuleResult:
    fired = features.urgency_keyword_count > 0
    return _result(
        rule_id="email.urgency_language",
        fired=fired,
        weight=10,
        severity="low",
        value=features.urgency_keyword_count,
        description="The message uses urgent or account-threat language.",
    )


def credential_request_rule(features: EmailFeatures) -> EmailRuleResult:
    fired = features.credential_keyword_count > 0
    return _result(
        rule_id="email.credential_request",
        fired=fired,
        weight=15,
        severity="medium",
        value=features.credential_keyword_count,
        description="The message asks for credentials or other sensitive verification.",
    )


def missing_core_headers_rule(features: EmailFeatures) -> EmailRuleResult:
    return _result(
        rule_id="email.missing_core_headers",
        fired=features.missing_core_headers,
        weight=10,
        severity="low",
        value=features.missing_core_headers,
        description="The message is missing Date or Message-ID headers.",
    )


DEFAULT_RULES: tuple[RuleFn, ...] = (
    display_name_domain_mismatch_rule,
    from_reply_to_mismatch_rule,
    auth_results_fail_rule,
    link_text_href_mismatch_rule,
    urgency_language_rule,
    credential_request_rule,
    missing_core_headers_rule,
)


def evaluate_rules(
    features: EmailFeatures,
    rules: tuple[RuleFn, ...] = DEFAULT_RULES,
) -> list[EmailRuleResult]:
    """Run the registered email heuristics in order."""
    return [rule(features) for rule in rules]
