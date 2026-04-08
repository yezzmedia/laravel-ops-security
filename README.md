# Laravel Ops Security

`yezzmedia/laravel-ops-security` is the operator-facing security posture and governance package for the Yezz Media Laravel platform.

It combines read-oriented posture checks for SSL, SSH, secrets, and security configuration with a central governance layer that aggregates package-declared security requests and requirements, verifies selected runtime controls, records visibility evidence, and renders the resulting operator workflow inside the shared ops panel.

## Version

Current release: `0.1.0`

## Requirements

- PHP `^8.4`
- Laravel `^13.0` components
- `filament/filament ^5.0`
- `spatie/laravel-package-tools ^1.93`
- `yezzmedia/laravel-foundation ^0.1`

Optional:

- `spatie/laravel-activitylog ^5.0` for persisted ops-security audit writes

## Installation

Install the package in the consuming Laravel application:

```bash
composer require yezzmedia/laravel-ops-security
```

The service provider is auto-discovered.

## Install flow

The package integrates with foundation through `website:install`.

```bash
php artisan website:install --only=yezzmedia/laravel-ops-security
php artisan website:install --only=yezzmedia/laravel-ops-security --migrate
```

The current install steps are:

- `VerifyOpenSslExtensionStep`
- `VerifyOpsDependencyStep`
- `EnsureOpsSecurityVisibilityStoreReadyInstallStep`
- `PublishSecurityConfigStep`

Important behavior:

- `yezzmedia/laravel-ops` must be present because ops-security contributes a page to the shared ops panel
- the OpenSSL extension must be available for certificate posture checks
- `--migrate` is required when the visibility store tables are missing
- the package can degrade safely when the visibility tables are not present, but request history and persisted evidence remain unavailable until the store is ready

## Configuration

Publish the config when you need to override defaults:

```bash
php artisan vendor:publish --provider="YezzMedia\OpsSecurity\OpsSecurityServiceProvider" --tag="config"
```

Key config sections in `config/ops-security.php`:

```php
return [
    'enabled' => true,

    'cache' => [
        'enabled' => true,
        'ttl' => 300,
        'store' => null,
    ],

    'ssl' => [
        'enabled' => true,
        'domains' => [],
        'timeout' => 10,
        'warning_days' => 30,
        'critical_days' => 7,
    ],

    'ssh' => [
        'enabled' => true,
        'key_directory' => null,
        'config_path' => null,
        'max_key_age_days' => 365,
    ],

    'secrets' => [
        'enabled' => true,
        'additional' => [],
        'minimum_length' => 16,
        'minimum_entropy' => 3.0,
    ],

    'config' => [
        'enabled' => true,
        'production_checks_only' => false,
        'session_max_lifetime' => 480,
        'minimum_bcrypt_rounds' => 12,
    ],

    'timeouts' => [
        'overall' => 30,
    ],

    'audit' => [
        'enabled' => true,
        'driver' => 'activitylog',
        'log_name' => 'ops-security',
    ],

    'visibility' => [
        'display_limit' => 25,
    ],
];
```

## What The Package Provides

### Security posture domains

The package currently resolves posture across four domains:

- SSL / TLS certificates
- SSH posture
- secret health
- security configuration

`OpsSecurityManager` exposes:

- `posture()`
- `refresh()`
- `domain()`
- `alerts()`
- `status()`
- `isCritical()`

Posture reads are memoized per request and may also use the configured cache store.

### Security governance aggregation

The package consumes security declarations from foundation registries:

- `SecurityRequestRegistry`
- `SecurityRequirementRegistry`

It then computes a governance summary that includes:

- grouped package requests and requirements
- effective controls
- verified, observed, unmet, and drift counts
- policy conflicts
- remediation recommendations

Current built-in verification strategies cover:

- `auth | login_throttle | ops-panel`
- `auth | password_confirmation | destructive-settings`
- `identity | privileged_mfa | super-admin`

When no package-owned verification strategy exists, the governance layer reports the control as observed instead of pretending it can enforce it.

### Visibility storage and evidence

The package exposes a broker-backed visibility model for security review:

- security requests
- security decisions
- runtime evidence

Persisted records live in:

- `ops_security_requests`
- `ops_security_decisions`
- `ops_security_runtime_evidence`

The default broker is `DatabaseSecurityRequestBroker`.

If the visibility tables are missing, the package still returns governance and posture summaries, but persisted visibility reads degrade safely until the store is ready.

### Masking and preview rules

Security request definitions can declare:

- a payload schema
- allowed preview fields
- masked preview fields

`SecurityPayloadSanitizer` applies those rules before request previews are rendered or persisted so the operator surface remains explicit without becoming a raw secret or identity dump.

### Operator page

The package registers `OpsSecurityPage` into the shared ops panel under the `Security` navigation group.

Current page sections include:

- Overview
- Governance Overview
- domain posture tabs
- Governance Details
- Visibility Overview
- Visibility Details
- Alerts
- actions section

The page requires `ops-security.posture.view` and exposes a manual refresh action for operators who also hold `ops-security.posture.refresh`.

Visibility sections keep full counters but render only the newest bounded records per section according to `visibility.display_limit` to avoid oversized Filament schemas on active hosts.

## Foundation registration surface

`OpsSecurityPlatformPackage` currently declares:

- permissions:
  - `ops-security.posture.view`
  - `ops-security.posture.refresh`
- feature:
  - `ops-security`
- audit event:
  - `security-posture-refreshed`
- ops module:
  - `ops-security`

It also declares security-governance metadata through foundation:

- requests:
  - `ops-security.request.auth.login-throttle`
  - `ops-security.request.identity.privileged-mfa`
- requirements:
  - `ops-security.auth.login-throttle`
  - `ops-security.identity.privileged-mfa`

These definitions let ops-security both consume the platform-wide governance surface and publish its own baseline operator security expectations.

## Audit integration

The package emits the `security-posture-refreshed` audit event through foundation metadata.

Audit writer behavior:

- `ops-security.audit.driver=activitylog`: use `ActivityLogSecurityAuditWriter`
- otherwise: use `NullSecurityAuditWriter`

If `activitylog` is configured but `spatie/laravel-activitylog` is not installed, the package fails explicitly during binding.

## Doctor checks

The package currently registers ten doctor checks:

- posture checks:
  - `SslPostureCheck`
  - `SshPostureCheck`
  - `SecretHealthCheck`
  - `SecurityConfigCheck`
  - `SecurityResolverCheck`
- governance checks:
  - `LoginThrottleCheck`
  - `PasswordConfirmationCheck`
  - `PrivilegedMfaCheck`
  - `SecurityDriftCheck`
  - `SecurityPolicyConflictCheck`

Together these checks cover both the read-oriented posture baseline and the central governance verification layer added in 008.

## Relationship to producer packages

Ops-security does not own every security implementation detail.

Current package boundaries are:

- `yezzmedia/laravel-ops` declares login-throttle intent for the ops panel
- `yezzmedia/laravel-access` emits privileged-account MFA visibility signals
- `yezzmedia/laravel-ops-settings` owns destructive-action password confirmation and declares that requirement centrally
- `yezzmedia/laravel-ops-security` aggregates, verifies, and reports on those signals and requirements

This keeps technical enforcement in the correct package or host layer while making drift and conflicts visible to operators.

## Testing

The package ships `YezzMedia\OpsSecurity\Tests\OpsSecurityTestCase` for consuming package tests.

Run the package test suite:

```bash
composer test
composer analyse
composer format
```

## License

Proprietary
