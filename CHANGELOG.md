# Changelog

All notable changes to `yezzmedia/laravel-ops-security` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning.

## [Unreleased]

### Added

- package README documenting the implemented posture, governance, visibility, audit, and operator-page surface
- package changelog for ongoing release tracking

## [0.1.0] - 2026-04-08

### Added

- foundation-aligned package bootstrap through `OpsSecurityPlatformPackage` and `OpsSecurityServiceProvider`
- Filament plugin integration for the shared ops panel through `OpsSecurityFilamentPlugin`
- security posture monitoring for:
  - SSL / TLS certificate health
  - SSH posture
  - secret health
  - security configuration diagnostics
- posture data layer:
  - `SecurityPostureSummary`
  - `DomainPostureResult`
  - `CertificatePosture`
  - `CertificateDetail`
  - `SshPosture`
  - `SshKeyInfo`
  - `SecretHealthResult`
  - `SecretCheckItem`
  - `SecurityConfigResult`
  - `SecurityConfigItem`
  - `SecurityAlert`
- governance and visibility data layer:
  - `EffectiveSecurityControl`
  - `SecurityGovernanceSummary`
  - `SecurityVisibilitySummary`
  - `SecurityRequestRecordData`
  - `SecurityDecisionRecordData`
  - `SecurityRuntimeEvidenceData`
- posture and governance manager runtime through `OpsSecurityManager`
- posture resolvers and helpers:
  - `SslPostureResolver`
  - `SshPostureResolver`
  - `SecretHealthResolver`
  - `SecurityConfigResolver`
  - `SecurityPostureSummaryBuilder`
  - `CertificateParser`
  - `EntropyAnalyzer`
  - `SecretDefinitionRegistry`
- visibility persistence and broker surface:
  - `DatabaseSecurityRequestBroker`
  - `OpsSecurityVisibilityStoreSetup`
  - `SecurityRequestRecord`
  - `SecurityDecisionRecord`
  - `SecurityRuntimeEvidence`
  - visibility migration `0001_create_ops_security_visibility_tables.php`
- operator-facing ops page `OpsSecurityPage` with posture, governance, visibility, alert, and refresh workflows
- package permissions:
  - `ops-security.posture.view`
  - `ops-security.posture.refresh`
- package feature `ops-security`
- ops module `ops-security`
- audit event `security-posture-refreshed`
- security-governance declarations through foundation:
  - requests:
    - `ops-security.request.auth.login-throttle`
    - `ops-security.request.identity.privileged-mfa`
  - requirements:
    - `ops-security.auth.login-throttle`
    - `ops-security.identity.privileged-mfa`
- install steps:
  - `VerifyOpenSslExtensionStep`
  - `VerifyOpsDependencyStep`
  - `EnsureOpsSecurityVisibilityStoreReadyInstallStep`
  - `PublishSecurityConfigStep`
- doctor diagnostics:
  - `SslPostureCheck`
  - `SshPostureCheck`
  - `SecretHealthCheck`
  - `SecurityConfigCheck`
  - `SecurityResolverCheck`
  - `LoginThrottleCheck`
  - `PasswordConfirmationCheck`
  - `PrivilegedMfaCheck`
  - `SecurityDriftCheck`
  - `SecurityPolicyConflictCheck`
- audit writer surface:
  - `SecurityAuditWriter`
  - `NullSecurityAuditWriter`
  - `ActivityLogSecurityAuditWriter`
  - `WriteSecurityAuditEntry`
- package testing support through `OpsSecurityTestCase`

### Changed

- the package evolved beyond the original read-only posture direction into a central governance and verification layer for package-declared security controls
- visibility rendering now preserves full counters while limiting rendered records per section to avoid oversized Filament schemas on active hosts
- governance reads now reuse one visibility snapshot per request so the operator page avoids repeated database reads for the same evidence set

### Documentation

- documented the final 0.1.0 package surface after the 008 rollout
