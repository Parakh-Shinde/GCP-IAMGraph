# Security Policy

## Supported versions

GCP IAMGraph is currently an early-stage security research project.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| Older versions | No |

Security fixes are applied to the latest release and the default branch.

## Reporting a vulnerability

Do not open a public GitHub issue for a vulnerability that could place users, credentials, IAM data, or cloud environments at risk.

Report security issues privately through:

- [GitHub private vulnerability reporting](https://github.com/Parakh-Shinde/GCP-IAMGraph/security/advisories/new)

Include the following information when possible:

- affected version or commit;
- vulnerable component;
- steps required to reproduce the issue;
- expected and actual behavior;
- potential security impact;
- logs, screenshots, or proof-of-concept details;
- suggested remediation, if known.

Sensitive credentials, real IAM exports, access tokens, service-account keys, and confidential organization information must not be included in the report.

## Response process

After receiving a report, the maintainer will:

1. review and validate the reported behavior;
2. determine its impact and affected versions;
3. develop and test an appropriate remediation;
4. coordinate disclosure with the reporter when necessary;
5. publish a security advisory or patched release when appropriate.

This is a student-maintained open-source project, so response times may vary. Valid reports will be handled as promptly as reasonably possible.

## Credential and data safety

GCP IAMGraph does not require live Google Cloud credentials for its included examples.

Before using or sharing exported IAM data:

- remove credentials and secrets;
- sanitize organization, folder, and project identifiers;
- replace real user and service-account names;
- exclude access tokens and service-account keys;
- avoid committing confidential IAM policies;
- review generated reports before publishing them.

## Project security boundaries

GCP IAMGraph performs read-only, offline analysis. It does not:

- modify Google Cloud IAM policies;
- create or delete service-account keys;
- exploit detected attack paths;
- authenticate to Google Cloud automatically;
- collect or transmit credentials;
- remediate findings automatically.

Findings should be reviewed by a qualified cloud-security practitioner before production changes are made.

## Responsible disclosure

Please allow reasonable time for validation and remediation before publicly disclosing an unresolved vulnerability. Good-faith security research and responsible disclosure are appreciated.

