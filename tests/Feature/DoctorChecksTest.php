<?php

declare(strict_types=1);

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

it('runs the ssl posture check', function (): void {
    $result = app(SslPostureCheck::class)->run();

    expect($result->key)->toBe('ops-security.ssl-posture')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the ssh posture check', function (): void {
    $result = app(SshPostureCheck::class)->run();

    expect($result->key)->toBe('ops-security.ssh-posture')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the secret health check', function (): void {
    $result = app(SecretHealthCheck::class)->run();

    expect($result->key)->toBe('ops-security.secret-health')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the security config check', function (): void {
    $result = app(SecurityConfigCheck::class)->run();

    expect($result->key)->toBe('ops-security.security-config')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the resolver check', function (): void {
    $result = app(SecurityResolverCheck::class)->run();

    expect($result->key)->toBe('ops-security.resolvers')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the login throttle check', function (): void {
    $result = app(LoginThrottleCheck::class)->run();

    expect($result->key)->toBe('ops-security.login-throttle')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the password confirmation check', function (): void {
    $result = app(PasswordConfirmationCheck::class)->run();

    expect($result->key)->toBe('ops-security.password-confirmation')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the privileged mfa check', function (): void {
    $result = app(PrivilegedMfaCheck::class)->run();

    expect($result->key)->toBe('ops-security.privileged-mfa')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the security drift check', function (): void {
    $result = app(SecurityDriftCheck::class)->run();

    expect($result->key)->toBe('ops-security.governance-drift')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});

it('runs the security policy conflict check', function (): void {
    $result = app(SecurityPolicyConflictCheck::class)->run();

    expect($result->key)->toBe('ops-security.policy-conflicts')
        ->and($result->package)->toBe('yezzmedia/laravel-ops-security')
        ->and($result->status)->toBeIn(['passed', 'warning', 'failed', 'skipped']);
});
