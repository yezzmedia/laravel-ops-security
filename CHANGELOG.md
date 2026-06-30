# Changelog

All notable changes to `yezzmedia/laravel-ops-security` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning.

## [Unreleased]

## [0.2.0] - 2026-06-30

### Changed

- Bumped minimum `yezzmedia/laravel-foundation` dependency to `^0.2`

## [0.1.3] - 2026-04-13

### Fixed

- shipped a null security audit driver by default so installs do not require `spatie/laravel-activitylog` unless audit persistence is explicitly enabled
- aligned package defaults with the supported null-writer runtime path and avoided unexpected activitylog requirements in Basecamp and other hosts without the optional audit backend

## [0.1.2] - 2026-04-13

### Fixed

- cleared the cached visibility-table snapshot after running security visibility migrations so install readiness checks observe the newly created tables
- kept Basecamp and other package installs from failing with a false "visibility store is still not ready" error immediately after migrations

### Added

- package README documenting the implemented posture, governance, visibility, audit, and operator-page surface
- package changelog for ongoing release tracking

## [0.1.1] - 2026-04-12

### Fixed

- required `yezzmedia/laravel-foundation:^0.1.1` so the published security package can rely on the shipped security-governance contracts at install time
- corrected the `DoctorCheck` and `InstallStep` imports to the implemented Foundation namespaces

### Documentation

- recorded the release-compatibility hotfix for package consumers

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
