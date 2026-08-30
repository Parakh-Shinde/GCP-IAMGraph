# Changelog

All notable changes to GCP IAMGraph are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-08-30

### Added

- Explainable authorization engine with explicit `ALLOW`, `DENY`, and `UNKNOWN` decisions.
- Structured allow and deny evidence for authorization evaluations.
- IAM deny-policy models with principal and permission exceptions.
- IAMGraph deny-policy parsing and validation.
- Inherited deny-policy evaluation across the resource hierarchy.
- Deterministic authorization evidence and impersonation-edge ordering.
- Authorization-aware project IAM escalation detection.
- Authorization-aware service-account key-creation paths.
- Authorization-aware Compute Engine and service-account `actAs` paths.
- Authorization-aware multi-hop service-account impersonation paths.
- End-to-end CLI tests for deny-policy evaluation.
- Reproducible deny-policy example environment.
- Dedicated authorization, parser, model, detection, and CLI integration tests.

### Changed

- Permission-based attack paths are confirmed only when all required authorization decisions return `ALLOW`.
- Applicable deny policies override matching allow grants.
- Unsupported or unevaluated conditions return `UNKNOWN`.
- `DENY` and `UNKNOWN` permissions no longer create confirmed attack paths.
- Attack-path evidence now identifies the permission evaluated for each authorization hop.
- Test coverage increased to more than 90%.

### Security

- Prevents false-positive attack paths when an inherited deny policy blocks a permission.
- Prevents conditional access from being silently treated as confirmed access.
- Preserves deny-rule principal and permission exceptions.
- Breaks multi-hop impersonation paths when any intermediate edge is denied or uncertain.

## [0.1.1] - 2026-08-29

### Added

- Cloud Asset Inventory JSONL parsing.
- Custom IAM role support.
- SARIF 2.1.0 reporting for GitHub Code Scanning.
- JSON and Graphviz attack-graph output.
- Repository evidence and reproducible demonstration reports.
- Coverage enforcement and expanded CI validation.

### Changed

- Improved package metadata and development dependencies.
- Improved CLI filesystem-error handling.
- Strengthened repository security documentation.

## [0.1.0] - 2026-08-29

### Added

- Initial GCP IAMGraph proof of concept.
- Resource hierarchy and inherited IAM allow bindings.
- Primitive Owner and Editor role detection.
- Public and globally authenticated access detection.
- Project IAM-policy modification detection.
- Service-account key-creation detection.
- Multi-hop service-account impersonation search.
- Markdown and JSON reporting.
- CI failure thresholds.

[Unreleased]: https://github.com/Parakh-Shinde/GCP-IAMGraph/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Parakh-Shinde/GCP-IAMGraph/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Parakh-Shinde/GCP-IAMGraph/releases/tag/v0.1.1
[0.1.0]: https://github.com/Parakh-Shinde/GCP-IAMGraph/releases/tag/v0.1.0