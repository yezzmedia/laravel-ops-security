<?php

declare(strict_types=1);

use YezzMedia\Foundation\Registry\PackageRegistry;
use YezzMedia\Foundation\Registry\SecurityRequestRegistry;
use YezzMedia\Foundation\Registry\SecurityRequirementRegistry;
use YezzMedia\OpsSecurity\OpsSecurityPlatformPackage;
use YezzMedia\OpsSecurity\OpsSecurityServiceProvider;

it('boots the ops-security service provider', function (): void {
    expect(app()->providerIsLoaded(OpsSecurityServiceProvider::class))->toBeTrue();
});

it('registers the platform package with foundation', function (): void {
    $registry = app(PackageRegistry::class);

    expect($registry->has('yezzmedia/laravel-ops-security'))->toBeTrue();
});

it('registers the correct package metadata', function (): void {
    $package = new OpsSecurityPlatformPackage;
    $metadata = $package->metadata();

    expect($metadata->name)->toBe('yezzmedia/laravel-ops-security')
        ->and($metadata->vendor)->toBe('yezzmedia')
        ->and($metadata->description)->not->toBeEmpty();
});

it('declares two permissions', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $permissions = $package->permissionDefinitions();
    $viewPermission = collect($permissions)->firstWhere('name', 'ops-security.posture.view');
    $refreshPermission = collect($permissions)->firstWhere('name', 'ops-security.posture.refresh');

    expect($permissions)
        ->toHaveCount(2)
        ->and(array_map(fn ($permission) => $permission->name, $permissions))
        ->toContain('ops-security.posture.view', 'ops-security.posture.refresh')
        ->and($viewPermission?->defaultRoleHints)->toBe(['super-admin'])
        ->and($refreshPermission?->defaultRoleHints)->toBe(['super-admin']);
});

it('declares one feature', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $features = $package->featureDefinitions();

    expect($features)
        ->toHaveCount(1)
        ->and($features[0]->name)->toBe('ops-security');
});

it('declares one audit event', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $events = $package->auditEventDefinitions();

    expect($events)->toHaveCount(1)
        ->and($events[0]->key)->toBe('security-posture-refreshed');
});

it('declares five doctor checks', function (): void {
    $package = new OpsSecurityPlatformPackage;

    expect($package->doctorChecks())->toHaveCount(10);
});

it('declares four install steps', function (): void {
    $package = new OpsSecurityPlatformPackage;

    expect($package->installSteps())->toHaveCount(4);
});

it('ships a bounded visibility display limit configuration', function (): void {
    expect(config('ops-security.visibility.display_limit'))->toBe(25);
});

it('declares one ops module', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $modules = $package->opsModuleDefinitions();

    expect($modules)->toHaveCount(1)
        ->and($modules[0]->key)->toBe('ops-security')
        ->and($modules[0]->type)->toBe('page');
});

it('declares two security requirements', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $requirements = $package->securityRequirementDefinitions();

    expect($requirements)
        ->toHaveCount(2)
        ->and(array_map(fn ($requirement) => $requirement->key, $requirements))
        ->toContain('ops-security.auth.login-throttle', 'ops-security.identity.privileged-mfa');
});

it('declares two security requests', function (): void {
    $package = new OpsSecurityPlatformPackage;

    $requests = $package->securityRequestDefinitions();

    expect($requests)
        ->toHaveCount(2)
        ->and(array_map(fn ($request) => $request->key, $requests))
        ->toContain('ops-security.request.auth.login-throttle', 'ops-security.request.identity.privileged-mfa');
});

it('registers security requests with foundation', function (): void {
    $registry = app(SecurityRequestRegistry::class);

    expect($registry->forPackage('yezzmedia/laravel-ops-security')->pluck('key')->all())
        ->toBe([
            'ops-security.request.auth.login-throttle',
            'ops-security.request.identity.privileged-mfa',
        ]);
});

it('registers security requirements with foundation', function (): void {
    $registry = app(SecurityRequirementRegistry::class);

    expect($registry->forPackage('yezzmedia/laravel-ops-security')->pluck('key')->all())
        ->toBe([
            'ops-security.auth.login-throttle',
            'ops-security.identity.privileged-mfa',
        ]);
});
