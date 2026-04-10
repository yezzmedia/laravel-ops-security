<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory;
use Illuminate\Support\Facades\DB;
use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;
use YezzMedia\Foundation\Registry\SecurityRequestRegistry;
use YezzMedia\Foundation\Registry\SecurityRequirementRegistry;
use YezzMedia\OpsSecurity\Contracts\SecurityRequestBroker;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\SecurityGovernanceSummary;
use YezzMedia\OpsSecurity\Data\SecurityPostureSummary;
use YezzMedia\OpsSecurity\Data\SecurityVisibilitySummary;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\OpsSecurityManager;
use YezzMedia\OpsSecurity\Support\OpsSecurityVisibilityStoreSetup;
use YezzMedia\OpsSecurity\Support\SecurityPostureSummaryBuilder;

it('produces a security posture summary', function (): void {
    $manager = app(OpsSecurityManager::class);
    $summary = $manager->posture();

    expect($summary)
        ->toBeInstanceOf(SecurityPostureSummary::class)
        ->and($summary->status)->toBeInstanceOf(SecurityPostureStatus::class)
        ->and($summary->resolvedAt)->toBeInstanceOf(CarbonImmutable::class);
});

it('resolves each security domain posture', function (SecurityDomain $domain): void {
    $manager = app(OpsSecurityManager::class);
    $result = $manager->domain($domain);

    expect($result)
        ->toBeInstanceOf(DomainPostureResult::class)
        ->and($result->domain)->toBe($domain)
        ->and($result->status)->toBeInstanceOf(SecurityPostureStatus::class)
        ->and($result->summary)->toBeString();
})->with(SecurityDomain::cases());

it('returns alerts as a list', function (): void {
    expect(app(OpsSecurityManager::class)->alerts())->toBeArray();
});

it('computes an overall security status', function (): void {
    expect(app(OpsSecurityManager::class)->status())->toBeInstanceOf(SecurityPostureStatus::class);
});

it('refreshes the posture and returns a fresh result', function (): void {
    $manager = app(OpsSecurityManager::class);

    $first = $manager->posture();
    $refreshed = $manager->refresh();

    expect($refreshed)
        ->toBeInstanceOf(SecurityPostureSummary::class)
        ->and($refreshed->resolvedAt->greaterThanOrEqualTo($first->resolvedAt))->toBeTrue();
});

it('builds a governance summary from declared security requirements', function (): void {
    $governance = app(OpsSecurityManager::class)->governance();

    expect($governance)
        ->toBeInstanceOf(SecurityGovernanceSummary::class)
        ->and($governance->requestCount)->toBe(2)
        ->and($governance->requirementCount)->toBe(2)
        ->and($governance->packageCount)->toBe(1)
        ->and($governance->conflictCount)->toBe(0)
        ->and($governance->verifiedCount)->toBe(0)
        ->and($governance->observedCount)->toBe(2)
        ->and($governance->driftCount)->toBe(0)
        ->and($governance->unmetCapabilityCount)->toBe(0)
        ->and($governance->remediationRecommendations)->toBe([])
        ->and(array_keys($governance->requirementsByPackage))->toBe(['yezzmedia/laravel-ops-security'])
        ->and(array_keys($governance->requestsByPackage))->toBe(['yezzmedia/laravel-ops-security'])
        ->and(array_map(fn ($control) => $control->control, $governance->effectiveControls))
        ->toContain('login_throttle', 'privileged_mfa');
});

it('flags conflicting governance declarations when disallowed and required controls overlap', function (): void {
    app(SecurityRequirementRegistry::class)->register(new SecurityRequirementDefinition(
        key: 'test.auth.login-throttle-disallowed',
        package: 'yezzmedia/test-package',
        domain: 'auth',
        control: 'login_throttle',
        level: 'disallowed',
        scope: 'ops-panel',
        description: 'Test conflicting declaration for login throttle.',
        enforcementMode: 'observe_only',
        appliesTo: ['login'],
    ));

    $governance = app(OpsSecurityManager::class)->governance();
    $control = collect($governance->effectiveControls)
        ->first(fn ($effectiveControl) => $effectiveControl->control === 'login_throttle' && $effectiveControl->scope === 'ops-panel');

    expect($governance->conflictCount)->toBe(1)
        ->and($governance->driftCount)->toBe(1)
        ->and($control)->not->toBeNull()
        ->and($control->hasConflict)->toBeTrue()
        ->and($control->level)->toBe('disallowed')
        ->and($control->verificationStatus)->toBe('drift');
});

it('verifies password confirmation controls when a producer runtime exposes the expected hooks', function (): void {
    if (! class_exists('YezzMedia\\OpsSettings\\Filament\\Pages\\OpsSettingsPage')) {
        eval('namespace YezzMedia\\OpsSettings\\Filament\\Pages; final class OpsSettingsPage { public function confirmPassword(string $password): bool { return true; } public function saveIdentity(): void {} public function applyPreset(string $preset): void {} public function importSnapshot(string $snapshot): void {} private function ensurePasswordConfirmed(string $action): bool { return true; } private function hasFreshPasswordConfirmation(): bool { return true; } }');
    }

    config()->set('ops-settings.security.password_confirmation.timeout', 900);

    app(SecurityRequestRegistry::class)->register(new SecurityRequestDefinition(
        key: 'ops-settings.request.auth.password-confirmation',
        package: 'yezzmedia/laravel-ops-settings',
        domain: 'auth',
        control: 'password_confirmation',
        scope: 'destructive-settings',
        requestedLevel: 'required',
        requestedEnforcementMode: 'package_owned',
        description: 'Package-owned password confirmation request.',
    ));

    app(SecurityRequirementRegistry::class)->register(new SecurityRequirementDefinition(
        key: 'ops-settings.auth.password-confirmation',
        package: 'yezzmedia/laravel-ops-settings',
        domain: 'auth',
        control: 'password_confirmation',
        level: 'required',
        scope: 'destructive-settings',
        description: 'Package-owned password confirmation requirement.',
        enforcementMode: 'package_owned',
    ));

    $control = app(OpsSecurityManager::class)->governanceControl('auth', 'password_confirmation', 'destructive-settings');

    expect($control)->not->toBeNull()
        ->and($control->verificationStatus)->toBe('verified')
        ->and($control->requestPackages)->toBe(['yezzmedia/laravel-ops-settings'])
        ->and($control->requestKeys)->toBe(['ops-settings.request.auth.password-confirmation']);
});

it('records requests decisions and runtime evidence for visibility', function (): void {
    $broker = app(SecurityRequestBroker::class);

    $decision = $broker->submit(
        'ops-security.request.auth.login-throttle',
        [
            'guard' => 'web',
            'audience' => 'operators',
            'ip_hash' => '203.0.113.42',
        ],
        source: 'tests.manager',
        actor: 'tester',
    );

    $evidence = $broker->recordRuntimeUsage(
        'ops-security.request.auth.login-throttle',
        [
            'guard' => 'web',
            'audience' => 'operators',
            'ip_hash' => '203.0.113.42',
        ],
        source: 'tests.runtime',
        actor: 'tester',
    );

    $visibility = app(OpsSecurityManager::class)->visibility();

    expect($decision->effectiveLevel)->toBe('required')
        ->and($decision->payloadPreview['ip_hash'])->toBe('***3.42')
        ->and($evidence->payloadPreview['ip_hash'])->toBe('***3.42')
        ->and($visibility)->toBeInstanceOf(SecurityVisibilitySummary::class)
        ->and($visibility->requestCount)->toBe(1)
        ->and($visibility->decisionCount)->toBe(1)
        ->and($visibility->runtimeEvidenceCount)->toBe(1)
        ->and($visibility->requestDisplayCount)->toBe(1)
        ->and($visibility->decisionDisplayCount)->toBe(1)
        ->and($visibility->runtimeEvidenceDisplayCount)->toBe(1)
        ->and($visibility->requests[0]->requestKey)->toBe('ops-security.request.auth.login-throttle')
        ->and($visibility->decisions[0]->requestKey)->toBe('ops-security.request.auth.login-throttle')
        ->and($visibility->runtimeEvidence[0]->requestKey)->toBe('ops-security.request.auth.login-throttle');
});

it('degrades visibility reads when the visibility store is unavailable', function (): void {
    app()->instance(OpsSecurityVisibilityStoreSetup::class, new class extends OpsSecurityVisibilityStoreSetup
    {
        public function storeReady(): bool
        {
            return false;
        }
    });

    $broker = app(SecurityRequestBroker::class);
    $decision = $broker->submit('ops-security.request.auth.login-throttle', ['guard' => 'web']);
    $evidence = $broker->recordRuntimeUsage('ops-security.request.auth.login-throttle', ['guard' => 'web']);
    $visibility = app(OpsSecurityManager::class)->visibility();

    expect($decision->requestKey)->toBe('ops-security.request.auth.login-throttle')
        ->and($evidence->requestKey)->toBe('ops-security.request.auth.login-throttle')
        ->and($visibility->requestCount)->toBe(0)
        ->and($visibility->decisionCount)->toBe(0)
        ->and($visibility->runtimeEvidenceCount)->toBe(0)
        ->and($visibility->requestDisplayCount)->toBe(0)
        ->and($visibility->decisionDisplayCount)->toBe(0)
        ->and($visibility->runtimeEvidenceDisplayCount)->toBe(0);
});

it('limits rendered visibility records while preserving full counts', function (): void {
    config()->set('ops-security.visibility.display_limit', 25);

    $broker = app(SecurityRequestBroker::class);

    foreach (range(1, 80) as $index) {
        $broker->submit('ops-security.request.auth.login-throttle', [
            'guard' => 'web',
            'index' => $index,
        ]);
    }

    $visibility = app(OpsSecurityManager::class)->visibility();

    expect($visibility->requestCount)->toBe(80)
        ->and($visibility->decisionCount)->toBe(80)
        ->and($visibility->requestDisplayCount)->toBe(25)
        ->and($visibility->decisionDisplayCount)->toBe(25)
        ->and(count($visibility->requests))->toBe(25)
        ->and(count($visibility->decisions))->toBe(25);
});

it('reuses a single visibility snapshot across governance and visibility reads', function (): void {
    app(SecurityRequestRegistry::class)->register(new SecurityRequestDefinition(
        key: 'access.request.identity.privileged-mfa',
        package: 'yezzmedia/laravel-access',
        domain: 'identity',
        control: 'privileged_mfa',
        scope: 'super-admin',
        requestedLevel: 'required',
        requestedEnforcementMode: 'observe_only',
        description: 'Access producer visibility request.',
    ));

    app(SecurityRequirementRegistry::class)->register(new SecurityRequirementDefinition(
        key: 'access.identity.privileged-mfa',
        package: 'yezzmedia/laravel-access',
        domain: 'identity',
        control: 'privileged_mfa',
        level: 'required',
        scope: 'super-admin',
        description: 'Access producer visibility requirement.',
        enforcementMode: 'observe_only',
    ));

    $broker = app(SecurityRequestBroker::class);
    $broker->submit('access.request.identity.privileged-mfa', ['role' => 'super-admin']);

    DB::flushQueryLog();
    DB::enableQueryLog();

    $manager = app(OpsSecurityManager::class);
    $manager->governance();
    $manager->visibility();

    $queries = collect(DB::getQueryLog())->pluck('query');

    expect($queries->filter(fn (string $query): bool => str_contains($query, "name = 'ops_security_requests'") && str_contains($query, 'sqlite_master'))->count())->toBeLessThanOrEqual(1)
        ->and($queries->filter(fn (string $query): bool => str_contains($query, "name = 'ops_security_decisions'") && str_contains($query, 'sqlite_master'))->count())->toBeLessThanOrEqual(1)
        ->and($queries->filter(fn (string $query): bool => str_contains($query, "name = 'ops_security_runtime_evidence'") && str_contains($query, 'sqlite_master'))->count())->toBeLessThanOrEqual(1)
        ->and($queries->filter(fn (string $query): bool => str_contains($query, 'from "ops_security_requests"'))->count())->toBe(1)
        ->and($queries->filter(fn (string $query): bool => str_contains($query, 'from "ops_security_decisions"'))->count())->toBe(1)
        ->and($queries->filter(fn (string $query): bool => str_contains($query, 'from "ops_security_runtime_evidence"'))->count())->toBe(1);
});

it('memoizes governance results across repeated governance reads', function (): void {
    $securityRequests = Mockery::mock(SecurityRequestRegistry::class);
    $securityRequirements = Mockery::mock(SecurityRequirementRegistry::class);

    $securityRequests->shouldReceive('all')
        ->once()
        ->andReturn(collect([
            new SecurityRequestDefinition(
                key: 'test.request.auth.session-hardening',
                package: 'yezzmedia/test-package',
                domain: 'auth',
                control: 'session_hardening',
                scope: 'ops-panel',
                requestedLevel: 'recommended',
                requestedEnforcementMode: 'observe_only',
                description: 'Test request for governance memoization.',
            ),
        ]));

    $securityRequirements->shouldReceive('all')
        ->once()
        ->andReturn(collect([
            new SecurityRequirementDefinition(
                key: 'test.auth.session-hardening',
                package: 'yezzmedia/test-package',
                domain: 'auth',
                control: 'session_hardening',
                level: 'recommended',
                scope: 'ops-panel',
                description: 'Test requirement for governance memoization.',
                enforcementMode: 'observe_only',
            ),
        ]));

    $manager = new OpsSecurityManager(
        resolvers: [],
        summaryBuilder: app(SecurityPostureSummaryBuilder::class),
        securityRequests: $securityRequests,
        securityRequirements: $securityRequirements,
        requestBroker: app(SecurityRequestBroker::class),
        cacheFactory: app(Factory::class),
        cacheEnabled: false,
        cacheStore: null,
        cacheTtl: 300,
        visibilityDisplayLimit: 25,
    );

    $first = $manager->governance();
    $control = $manager->governanceControl('auth', 'session_hardening', 'ops-panel');
    $second = $manager->governance();

    expect($first)
        ->toBeInstanceOf(SecurityGovernanceSummary::class)
        ->and($second)->toBe($first)
        ->and($control)->not->toBeNull()
        ->and($control->verificationStatus)->toBe('observed')
        ->and($control->verificationSummary)->toContain('no runtime verification strategy is registered yet');
});
