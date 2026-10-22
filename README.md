# Azure Guardrail

Assess Azure Terraform plans before deployment: flag risky settings, explain their impact, and suggest safer configurations.

This Python starter runs locally, requires no Azure credentials, and never deploys or modifies infrastructure. It uses only the Python standard library.

## Quick start

Requires Python 3.10 or newer. Run from the project directory:

```sh
python -m azure_guardrail examples/risky-plan.json
python -m azure_guardrail examples/safe-plan.json --json
python -m unittest discover -s tests -v
```

On Windows, use `py` instead of `python` if that is your installed Python launcher. The risky example exits with code 1; the safe example exits with code 0.

## Scan a real plan

In your Terraform project, create a saved plan and export it to JSON:

```sh
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

Then, from this project, run:

```sh
python -m azure_guardrail /path/to/tfplan.json
```

Use UTF-8 for the export (the commands above work in PowerShell 7 and POSIX shells). Saved plans and JSON exports can contain secrets. Do not commit them or publish them as public CI artifacts. Reports include resource addresses but omit raw resource values.

## Initial security baseline

The first four checks cover managed `azurerm_storage_account` resources from the official AzureRM provider, using current AzureRM 4.x field names.

| ID | Severity | Check | Safer configuration |
| --- | --- | --- | --- |
| AZG001 | High | Require encrypted transport | `https_traffic_only_enabled = true` |
| AZG002 | High | Require TLS 1.2 or newer | `min_tls_version = "TLS1_2"` |
| AZG003 | High | Prevent nested items opting into public access | `allow_nested_items_to_be_public = false` |
| AZG004 | Medium | Disable the public network endpoint | `public_network_access_enabled = false` |

AZG003 identifies permission to enable public access, not proof that a container is public. AZG004 is a conservative private-network baseline: public network access does not imply anonymous or unrestricted access. Configure private endpoints and DNS and verify application connectivity before disabling a public endpoint.

Each finding includes a rule ID, severity, resource address, explanation, and suggested Terraform setting. Missing, null, unknown, or unsupported values produce **review** findings rather than being counted as safe. Provider defaults are not inferred.

## Behavior and exit codes

The scanner reads `resource_changes` and checks planned `after` values, including unchanged resources listed in the plan. Replacements are checked using their future settings. Data sources, pure deletions, other providers, and unsupported resource types are skipped and counted.

- `0`: no findings in the checks assessed.
- `1`: at least one risk or unresolved review finding.
- `2`: invalid input, unsupported plan format, or usage error.

Use `--json` for machine-readable output. Always review coverage counts: zero findings is not a security certification, and a plan with no supported resources assesses nothing. The scanner supports Terraform JSON format major version 1 and rejects errored or explicitly incomplete plans. Targeted plans may provide limited coverage.

## Baseline files

- `azure_guardrail/rules.py`: rule definitions and security explanations.
- `azure_guardrail/scanner.py`: plan validation and assessment.
- `azure_guardrail/__main__.py`: command-line input, reports, and exit codes.
- `examples/`: synthetic plans that demonstrate risky and safer settings.
- `tests/`: scanner and command-line regression tests.
- `pyproject.toml`: Python project metadata; no runtime dependencies.
- `.github/workflows/tests.yml`: automated tests on pushes and pull requests.

## Limitations and next steps

This is a focused initial baseline. It does not inspect live Azure, parse Terraform source, evaluate cross-resource relationships, or assess all Azure services. It does not automatically rewrite configuration. Older AzureRM field names require review.

Next steps: network security group ingress checks, Key Vault protections, configurable severity thresholds, and reviewed exceptions with expiration dates. Add behavioral tests and document limitations for every new rule.

## References

- [Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format)
- [AzureRM storage account reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account)
