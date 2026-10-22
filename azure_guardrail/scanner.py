"""Assess future resource settings from Terraform's JSON plan format."""

import re

from .rules import RULES

PROVIDER = "registry.terraform.io/hashicorp/azurerm"
ACTIONS = {("no-op",), ("create",), ("update",), ("delete",),
           ("read",), ("delete", "create"), ("create", "delete")}


def assess(plan):
    """Return findings and coverage counts, or raise ValueError for invalid input."""
    if (not isinstance(plan, dict)
            or not isinstance(plan.get("format_version"), str)
            or not re.fullmatch(r"1\.\d+", plan["format_version"])
            or not isinstance(plan.get("planned_values"), dict)
            or not isinstance(plan.get("resource_changes", []), list)):
        raise ValueError("Expected a Terraform JSON plan with format_version 1.x and planned_values.")
    if plan.get("errored") is True or plan.get("complete") is False:
        raise ValueError("Cannot assess an errored or incomplete Terraform plan.")
    findings = []
    summary = dict(assessed_resources=0, skipped_resources=0, risk_findings=0, review_findings=0)
    for resource in plan.get("resource_changes", []):
        if (not isinstance(resource, dict)
                or not all(isinstance(resource.get(key), str)
                           for key in ("address", "type", "provider_name"))
                or resource.get("mode") not in ("managed", "data")
                or not isinstance(resource.get("change"), dict)):
            raise ValueError("Malformed resource change in Terraform plan.")
        change = resource["change"]
        actions = change.get("actions")
        if (not isinstance(actions, list) or not all(isinstance(a, str) for a in actions)
                or tuple(actions) not in ACTIONS):
            raise ValueError("Unsupported or malformed resource change actions.")
        if (resource["mode"] != "managed" or resource["provider_name"] != PROVIDER
                or resource["type"] != "azurerm_storage_account" or actions == ["delete"]):
            summary["skipped_resources"] += 1
            continue
        after = change.get("after")
        unknown = change.get("after_unknown", {})
        if not isinstance(after, dict) or not (isinstance(unknown, dict) or unknown is True):
            raise ValueError("Expected planned values for a supported resource.")
        summary["assessed_resources"] += 1
        for rule in RULES:
            value = after.get(rule.field)
            review = (unknown is True or unknown.get(rule.field, False) is not False
                      or not rule.recognizes(value))
            if not review and value in rule.safe:
                continue
            status = "review" if review else "risk"
            findings.append(dict(
                id=rule.id, severity=rule.severity, status=status,
                resource=resource["address"], field=rule.field,
                title=f"Verify {rule.field}" if review else rule.title,
                why=("The planned value is missing, unknown, or unsupported. " if review else "") + rule.why,
                suggestion=rule.suggestion,
            ))
            summary[f"{status}_findings"] += 1
    return dict(findings=findings, summary=summary)
