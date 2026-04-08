<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity;

use YezzMedia\Foundation\Contracts\DefinesAuditEvents;
use YezzMedia\Foundation\Contracts\DefinesInstallSteps;
use YezzMedia\Foundation\Contracts\DefinesPermissions;
use YezzMedia\Foundation\Contracts\DefinesSecurityRequests;
use YezzMedia\Foundation\Contracts\DefinesSecurityRequirements;
use YezzMedia\Foundation\Contracts\DoctorCheck;
use YezzMedia\Foundation\Contracts\InstallStep;
use YezzMedia\Foundation\Contracts\PlatformPackage;
use YezzMedia\Foundation\Contracts\ProvidesDoctorChecks;
use YezzMedia\Foundation\Contracts\ProvidesOpsModules;
use YezzMedia\Foundation\Contracts\RegistersFeatures;
use YezzMedia\Foundation\Data\AuditEventDefinition;
use YezzMedia\Foundation\Data\FeatureDefinition;
use YezzMedia\Foundation\Data\OpsModuleDefinition;
use YezzMedia\Foundation\Data\PackageMetadata;
use YezzMedia\Foundation\Data\PermissionDefinition;
use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;
use YezzMedia\OpsSecurity\Doctor\LoginThrottleCheck;
use YezzMedia\OpsSecurity\Doctor\PasswordConfirmationCheck;
use YezzMedia\OpsSecurity\Doctor\PrivilegedMfaCheck;
use YezzMedia\OpsSecurity\Doctor\SecretHealthCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityConfigCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityDriftCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityPolicyConflictCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityResolverCheck;
use YezzMedia\OpsSecurity\Doctor\SshPostureCheck;
use YezzMedia\OpsSecurity\Doctor\SslPostureCheck;
use YezzMedia\OpsSecurity\Install\EnsureOpsSecurityVisibilityStoreReadyInstallStep;
use YezzMedia\OpsSecurity\Install\PublishSecurityConfigStep;
use YezzMedia\OpsSecurity\Install\VerifyOpenSslExtensionStep;
use YezzMedia\OpsSecurity\Install\VerifyOpsDependencyStep;

final class OpsSecurityPlatformPackage implements DefinesAuditEvents, DefinesInstallSteps, DefinesPermissions, DefinesSecurityRequests, DefinesSecurityRequirements, PlatformPackage, ProvidesDoctorChecks, ProvidesOpsModules, RegistersFeatures
{
    public function metadata(): PackageMetadata
    {
        return new PackageMetadata(
            name: 'yezzmedia/laravel-ops-security',
            vendor: 'yezzmedia',
            description: 'Security posture monitoring for the Yezz Media Laravel website platform.',
            packageClass: self::class,
        );
    }

    /**
     * @return array<int, PermissionDefinition>
     */
    public function permissionDefinitions(): array
    {
        return [
            new PermissionDefinition(
                name: 'ops-security.posture.view',
                package: 'yezzmedia/laravel-ops-security',
                label: 'View Security Posture',
                description: 'View the security posture dashboard and all domain results.',
                defaultRoleHints: ['super-admin'],
            ),
            new PermissionDefinition(
                name: 'ops-security.posture.refresh',
                package: 'yezzmedia/laravel-ops-security',
                label: 'Refresh Security Posture',
                description: 'Trigger a manual refresh of the security posture data.',
                defaultRoleHints: ['super-admin'],
            ),
        ];
    }

    /**
     * @return array<int, FeatureDefinition>
     */
    public function featureDefinitions(): array
    {
        return [
            new FeatureDefinition(
                name: 'ops-security',
                package: 'yezzmedia/laravel-ops-security',
                label: 'OPS Security',
                description: 'Security posture monitoring with SSL, SSH, secret health, and configuration checks.',
            ),
        ];
    }

    /**
     * @return array<int, AuditEventDefinition>
     */
    public function auditEventDefinitions(): array
    {
        return [
            new AuditEventDefinition(
                key: 'security-posture-refreshed',
                package: 'yezzmedia/laravel-ops-security',
                action: 'refreshed',
                subjectType: 'ops-security',
                description: 'Security posture data was refreshed.',
                severity: 'info',
                contextKeys: [
                    'status',
                    'domain_statuses',
                    'alert_count',
                    'critical_count',
                    'warning_count',
                    'triggered_by',
                    'resolver_duration_ms',
                ],
            ),
        ];
    }

    /**
     * @return array<int, InstallStep>
     */
    public function installSteps(): array
    {
        return [
            app(VerifyOpenSslExtensionStep::class),
            app(VerifyOpsDependencyStep::class),
            app(EnsureOpsSecurityVisibilityStoreReadyInstallStep::class),
            app(PublishSecurityConfigStep::class),
        ];
    }

    /**
     * @return array<int, DoctorCheck>
     */
    public function doctorChecks(): array
    {
        return [
            app(SslPostureCheck::class),
            app(SshPostureCheck::class),
            app(SecretHealthCheck::class),
            app(SecurityConfigCheck::class),
            app(SecurityResolverCheck::class),
            app(LoginThrottleCheck::class),
            app(PasswordConfirmationCheck::class),
            app(PrivilegedMfaCheck::class),
            app(SecurityDriftCheck::class),
            app(SecurityPolicyConflictCheck::class),
        ];
    }

    /**
     * @return array<int, OpsModuleDefinition>
     */
    public function opsModuleDefinitions(): array
    {
        return [
            new OpsModuleDefinition(
                key: 'ops-security',
                package: 'yezzmedia/laravel-ops-security',
                label: 'Security Posture',
                type: 'page',
                permissionHint: 'ops-security.posture.view',
            ),
        ];
    }

    /**
     * @return array<int, SecurityRequestDefinition>
     */
    public function securityRequestDefinitions(): array
    {
        return [
            new SecurityRequestDefinition(
                key: 'ops-security.request.auth.login-throttle',
                package: 'yezzmedia/laravel-ops-security',
                domain: 'auth',
                control: 'login_throttle',
                scope: 'ops-panel',
                requestedLevel: 'required',
                requestedEnforcementMode: 'observe_only',
                description: 'Packages may submit operator-login throttle requests for security review and visibility.',
                payloadSchema: [
                    'guard' => 'Target authentication guard.',
                    'audience' => 'Target audience segment.',
                    'ip_hash' => 'Masked or hashed network reference.',
                ],
                allowedPreviewFields: ['guard', 'audience', 'ip_hash'],
                maskedFields: ['ip_hash'],
                notes: 'Preview data remains masked for sensitive network identifiers.',
            ),
            new SecurityRequestDefinition(
                key: 'ops-security.request.identity.privileged-mfa',
                package: 'yezzmedia/laravel-ops-security',
                domain: 'identity',
                control: 'privileged_mfa',
                scope: 'super-admin',
                requestedLevel: 'recommended',
                requestedEnforcementMode: 'observe_only',
                description: 'Packages may submit privileged-account MFA hardening requests for central review.',
                payloadSchema: [
                    'role' => 'Affected privileged role.',
                    'channel' => 'Requested hardening channel such as totp or passkey.',
                    'actor_reference' => 'Masked actor reference or operator identifier.',
                ],
                allowedPreviewFields: ['role', 'channel', 'actor_reference'],
                maskedFields: ['actor_reference'],
                notes: 'This request surface is for visibility and policy review, not raw credential transport.',
            ),
        ];
    }

    /**
     * @return array<int, SecurityRequirementDefinition>
     */
    public function securityRequirementDefinitions(): array
    {
        return [
            new SecurityRequirementDefinition(
                key: 'ops-security.auth.login-throttle',
                package: 'yezzmedia/laravel-ops-security',
                domain: 'auth',
                control: 'login_throttle',
                level: 'required',
                scope: 'ops-panel',
                description: 'Operational authentication entry points must be protected by login throttling.',
                enforcementMode: 'observe_only',
                appliesTo: ['login'],
                notes: 'Producer packages may require stricter limits, but they should not weaken this baseline.',
            ),
            new SecurityRequirementDefinition(
                key: 'ops-security.identity.privileged-mfa',
                package: 'yezzmedia/laravel-ops-security',
                domain: 'identity',
                control: 'privileged_mfa',
                level: 'recommended',
                scope: 'super-admin',
                description: 'Privileged operator accounts should use additional authentication hardening such as MFA or passkeys.',
                enforcementMode: 'observe_only',
                appliesTo: ['ops-panel', 'account-security'],
                notes: 'V1 governance observes and reports this posture without owning the Fortify or passkey implementation flow.',
            ),
        ];
    }
}
