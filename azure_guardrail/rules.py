"""Explicit policies; do not infer provider defaults from missing values."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    field: str
    title: str
    why: str
    suggestion: str
    allowed: tuple
    safe: tuple

    def recognizes(self, value):
        # JSON numbers (0/1) must not be accepted as Python booleans.
        return any(type(value) is type(item) and value == item for item in self.allowed)


RULES = (
    Rule("AZG001", "high", "https_traffic_only_enabled",
         "Storage permits HTTP transport",
         "Unencrypted transport can expose data in transit.",
         "https_traffic_only_enabled = true", (True, False), (True,)),
    Rule("AZG002", "high", "min_tls_version",
         "Storage permits legacy TLS",
         "Older TLS versions provide weaker transport protection.",
         'min_tls_version = "TLS1_2"',
         ("TLS1_0", "TLS1_1", "TLS1_2", "TLS1_3"), ("TLS1_2", "TLS1_3")),
    Rule("AZG003", "high", "allow_nested_items_to_be_public",
         "Storage allows items to opt into public access",
         "Containers may be configured for anonymous reads. This setting alone does not prove a container is public.",
         "allow_nested_items_to_be_public = false", (True, False), (False,)),
    Rule("AZG004", "medium", "public_network_access_enabled",
         "Storage public network access is enabled",
         "A public endpoint increases network exposure even when authentication and firewall restrictions apply.",
         "public_network_access_enabled = false # Configure private endpoints and DNS and verify connectivity first.",
         (True, False), (False,)),
)
