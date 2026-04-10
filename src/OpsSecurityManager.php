<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;
use YezzMedia\Foundation\Registry\SecurityRequestRegistry;
use YezzMedia\Foundation\Registry\SecurityRequirementRegistry;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Contracts\SecurityRequestBroker;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\EffectiveSecurityControl;
use YezzMedia\OpsSecurity\Data\SecurityAlert;
use YezzMedia\OpsSecurity\Data\SecurityGovernanceSummary;
use YezzMedia\OpsSecurity\Data\SecurityPostureSummary;
use YezzMedia\OpsSecurity\Data\SecurityVisibilitySummary;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Support\DatabaseSecurityRequestBroker;
use YezzMedia\OpsSecurity\Support\SecurityPostureSummaryBuilder;

class OpsSecurityManager
{
    private const CACHE_KEY = 'ops-security:posture';

    private ?SecurityPostureSummary $memo = null;

    private ?SecurityGovernanceSummary $governanceMemo = null;

    private ?CacheRepository $cache = null;

    /**
     * @var array{requests: array<int, mixed>, decisions: array<int, mixed>, runtimeEvidence: array<int, mixed>}|null
     */
    private ?array $visibilityRecords = null;

    /**
     * @param  array<SecurityPostureResolver>  $resolvers
     */
    public function __construct(
        private readonly array $resolvers,
        private readonly SecurityPostureSummaryBuilder $summaryBuilder,
        private readonly SecurityRequestRegistry $securityRequests,
        private readonly SecurityRequirementRegistry $securityRequirements,
        private readonly SecurityRequestBroker $requestBroker,
        private readonly CacheFactory $cacheFactory,
        private readonly bool $cacheEnabled,
        private readonly ?string $cacheStore,
        private readonly int $cacheTtl,
        private readonly int $visibilityDisplayLimit,
    ) {}

    /**
     * Get the current posture (cached or fresh).
     */
    public function posture(): SecurityPostureSummary
    {
        if ($this->memo !== null) {
            return $this->memo;
        }

        if ($this->cacheEnabled) {
            $cached = $this->resolveCache()->get(self::CACHE_KEY);
            if ($cached instanceof SecurityPostureSummary) {
                $this->memo = $cached;

                return $this->memo;
            }
        }

        return $this->computeAndStore();
    }

    /**
     * Force-resolve all domains, update cache.
     */
    public function refresh(): SecurityPostureSummary
    {
        $this->memo = null;
        $this->governanceMemo = null;

        if ($this->cacheEnabled) {
            $this->resolveCache()->forget(self::CACHE_KEY);
        }

        return $this->computeAndStore();
    }

    /**
     * Get a single domain result from the current posture.
     */
    public function domain(SecurityDomain $domain): DomainPostureResult
    {
        $posture = $this->posture();

        return $posture->domains[$domain->value] ?? new DomainPostureResult(
            domain: $domain,
            status: SecurityPostureStatus::Unknown,
            summary: 'Domain not resolved.',
            items: [],
            checkedAt: CarbonImmutable::now(),
            durationMs: 0,
        );
    }

    /**
     * Get alerts from the current posture.
     *
     * @return array<SecurityAlert>
     */
    public function alerts(): array
    {
        return $this->posture()->alerts;
    }

    /**
     * Get the overall status from the current posture.
     */
    public function status(): SecurityPostureStatus
    {
        return $this->posture()->status;
    }

    /**
     * Whether any domain is critical.
     */
    public function isCritical(): bool
    {
        return $this->status() === SecurityPostureStatus::Critical;
    }

    public function governance(): SecurityGovernanceSummary
    {
        if ($this->governanceMemo !== null) {
            return $this->governanceMemo;
        }

        /** @var array<int, SecurityRequestDefinition> $requests */
        $requests = $this->securityRequests
            ->all()
            ->sortBy([
                ['package', 'asc'],
                ['key', 'asc'],
            ])
            ->values()
            ->all();

        /** @var array<int, SecurityRequirementDefinition> $requirements */
        $requirements = $this->securityRequirements
            ->all()
            ->sortBy([
                ['package', 'asc'],
                ['key', 'asc'],
            ])
            ->values()
            ->all();

        /** @var array<string, array<int, SecurityRequirementDefinition>> $requirementsByPackage */
        $requirementsByPackage = collect($requirements)
            ->groupBy('package')
            ->map(static fn ($packageRequirements) => $packageRequirements->values()->all())
            ->all();

        /** @var array<string, array<int, SecurityRequestDefinition>> $requestsByPackage */
        $requestsByPackage = collect($requests)
            ->groupBy('package')
            ->map(static fn ($packageRequests) => $packageRequests->values()->all())
            ->all();

        $effectiveControls = $this->buildEffectiveControls($requests, $requirements);

        $verifiedCount = count(array_filter(
            $effectiveControls,
            static fn (EffectiveSecurityControl $control): bool => $control->verificationStatus === 'verified',
        ));

        $observedCount = count(array_filter(
            $effectiveControls,
            static fn (EffectiveSecurityControl $control): bool => $control->verificationStatus === 'observed',
        ));

        $driftCount = count(array_filter(
            $effectiveControls,
            static fn (EffectiveSecurityControl $control): bool => $control->verificationStatus === 'drift',
        ));

        $unmetCapabilityCount = count(array_filter(
            $effectiveControls,
            static fn (EffectiveSecurityControl $control): bool => $control->verificationStatus === 'unmet',
        ));

        $remediationRecommendations = collect($effectiveControls)
            ->flatMap(static fn (EffectiveSecurityControl $control): array => $control->recommendedActions)
            ->filter(static fn (string $recommendation): bool => $recommendation !== '')
            ->unique()
            ->values()
            ->all();

        return $this->governanceMemo = new SecurityGovernanceSummary(
            requestsByPackage: $requestsByPackage,
            requirementsByPackage: $requirementsByPackage,
            effectiveControls: $effectiveControls,
            requestCount: count($requests),
            requirementCount: count($requirements),
            packageCount: count(array_unique([...array_keys($requestsByPackage), ...array_keys($requirementsByPackage)])),
            conflictCount: count(array_filter(
                $effectiveControls,
                static fn (EffectiveSecurityControl $control): bool => $control->hasConflict,
            )),
            verifiedCount: $verifiedCount,
            observedCount: $observedCount,
            driftCount: $driftCount,
            unmetCapabilityCount: $unmetCapabilityCount,
            remediationRecommendations: $remediationRecommendations,
        );
    }

    public function governanceControl(string $domain, string $control, string $scope): ?EffectiveSecurityControl
    {
        return collect($this->governance()->effectiveControls)
            ->first(static fn (EffectiveSecurityControl $effectiveControl): bool => $effectiveControl->domain === $domain
                && $effectiveControl->control === $control
                && $effectiveControl->scope === $scope);
    }

    public function visibility(): SecurityVisibilitySummary
    {
        if ($this->requestBroker instanceof DatabaseSecurityRequestBroker) {
            return $this->requestBroker->visibilitySummary($this->visibilityDisplayLimit);
        }

        $records = $this->visibilityRecords();
        $requests = $records['requests'];
        $decisions = $records['decisions'];
        $runtimeEvidence = $records['runtimeEvidence'];

        $limitedRequests = array_slice($requests, 0, $this->visibilityDisplayLimit);
        $limitedDecisions = array_slice($decisions, 0, $this->visibilityDisplayLimit);
        $limitedRuntimeEvidence = array_slice($runtimeEvidence, 0, $this->visibilityDisplayLimit);

        return new SecurityVisibilitySummary(
            requests: $limitedRequests,
            decisions: $limitedDecisions,
            runtimeEvidence: $limitedRuntimeEvidence,
            requestCount: count($requests),
            decisionCount: count($decisions),
            runtimeEvidenceCount: count($runtimeEvidence),
            conflictDecisionCount: count(array_filter(
                $decisions,
                static fn ($decision): bool => $decision->hasConflict,
            )),
            requestDisplayCount: count($limitedRequests),
            decisionDisplayCount: count($limitedDecisions),
            runtimeEvidenceDisplayCount: count($limitedRuntimeEvidence),
        );
    }

    /**
     * @return array{requests: array<int, mixed>, decisions: array<int, mixed>, runtimeEvidence: array<int, mixed>}
     */
    private function visibilityRecords(): array
    {
        if ($this->visibilityRecords !== null) {
            return $this->visibilityRecords;
        }

        return $this->visibilityRecords = [
            'requests' => $this->requestBroker->requests(),
            'decisions' => $this->requestBroker->decisions(),
            'runtimeEvidence' => $this->requestBroker->runtimeEvidence(),
        ];
    }

    /**
     * @param  array<int, SecurityRequestDefinition>  $requests
     * @param  array<int, SecurityRequirementDefinition>  $requirements
     * @return array<int, EffectiveSecurityControl>
     */
    private function buildEffectiveControls(array $requests, array $requirements): array
    {
        $requestsByControl = collect($requests)
            ->groupBy(static fn (SecurityRequestDefinition $request): string => implode('|', [
                $request->domain,
                $request->control,
                $request->scope,
            ]));

        $requirementsByControl = collect($requirements)
            ->groupBy(static fn (SecurityRequirementDefinition $requirement): string => implode('|', [
                $requirement->domain,
                $requirement->control,
                $requirement->scope,
            ]));

        return collect(array_values(array_unique([
            ...array_keys($requestsByControl->all()),
            ...array_keys($requirementsByControl->all()),
        ])))
            ->map(function (string $controlKey) use ($requestsByControl, $requirementsByControl): EffectiveSecurityControl {
                /** @var array<int, SecurityRequestDefinition> $requestDefinitions */
                $requestDefinitions = $requestsByControl->get($controlKey)?->values()->all() ?? [];
                /** @var array<int, SecurityRequirementDefinition> $requirementDefinitions */
                $requirementDefinitions = $requirementsByControl->get($controlKey)?->values()->all() ?? [];

                $referenceDefinition = $requirementDefinitions[0] ?? $requestDefinitions[0];

                $levels = array_values(array_unique(array_map(
                    static fn (SecurityRequirementDefinition $requirement): string => $requirement->level,
                    $requirementDefinitions,
                )));

                $requestedLevels = array_values(array_unique(array_map(
                    static fn (SecurityRequestDefinition $request): string => $request->requestedLevel,
                    $requestDefinitions,
                )));

                $enforcementModes = array_values(array_unique(array_map(
                    static fn (SecurityRequirementDefinition $requirement): string => $requirement->enforcementMode,
                    $requirementDefinitions,
                )));

                $requestedEnforcementModes = array_values(array_unique(array_map(
                    static fn (SecurityRequestDefinition $request): string => $request->requestedEnforcementMode,
                    $requestDefinitions,
                )));

                $hasConflict = in_array('disallowed', $levels, true)
                    && count(array_diff($levels, ['disallowed'])) > 0;

                $effectiveLevel = $this->resolveEffectiveLevel($levels !== [] ? $levels : $requestedLevels);
                $effectiveEnforcementMode = $this->resolveEffectiveEnforcementMode($enforcementModes !== [] ? $enforcementModes : $requestedEnforcementModes);
                $packages = array_values(array_unique(array_map(
                    static fn (SecurityRequirementDefinition $requirement): string => $requirement->package,
                    $requirementDefinitions,
                )));
                $requestPackages = array_values(array_unique(array_map(
                    static fn (SecurityRequestDefinition $request): string => $request->package,
                    $requestDefinitions,
                )));

                $verification = $this->verifyControl(
                    domain: $referenceDefinition->domain,
                    control: $referenceDefinition->control,
                    scope: $referenceDefinition->scope,
                    packages: array_values(array_unique([...$packages, ...$requestPackages])),
                    requestPackages: $requestPackages,
                    effectiveLevel: $effectiveLevel,
                    effectiveEnforcementMode: $effectiveEnforcementMode,
                    hasConflict: $hasConflict,
                    conflictReason: $hasConflict
                        ? 'Conflicting declarations mix disallowed requirements with non-disallowed policy expectations.'
                        : null,
                );

                return new EffectiveSecurityControl(
                    domain: $referenceDefinition->domain,
                    control: $referenceDefinition->control,
                    scope: $referenceDefinition->scope,
                    level: $effectiveLevel,
                    enforcementMode: $effectiveEnforcementMode,
                    packages: $packages,
                    requirementKeys: array_values(array_map(
                        static fn (SecurityRequirementDefinition $requirement): string => $requirement->key,
                        $requirementDefinitions,
                    )),
                    requestKeys: array_values(array_map(
                        static fn (SecurityRequestDefinition $request): string => $request->key,
                        $requestDefinitions,
                    )),
                    requestPackages: $requestPackages,
                    requestedLevels: $requestedLevels,
                    requestedEnforcementModes: $requestedEnforcementModes,
                    verificationStatus: $verification['status'],
                    verificationSummary: $verification['summary'],
                    hasConflict: $hasConflict,
                    conflictReason: $hasConflict
                        ? 'Conflicting declarations mix disallowed requirements with non-disallowed policy expectations.'
                        : null,
                    driftReason: $verification['driftReason'],
                    missingCapabilities: $verification['missingCapabilities'],
                    recommendedActions: $verification['recommendedActions'],
                );
            })
            ->sortBy([
                ['domain', 'asc'],
                ['control', 'asc'],
                ['scope', 'asc'],
            ])
            ->values()
            ->all();
    }

    /**
     * @param  array<int, string>  $packages
     * @param  array<int, string>  $requestPackages
     * @return array{status: string, summary: string, driftReason: string|null, missingCapabilities: array<int, string>, recommendedActions: array<int, string>}
     */
    private function verifyControl(
        string $domain,
        string $control,
        string $scope,
        array $packages,
        array $requestPackages,
        string $effectiveLevel,
        string $effectiveEnforcementMode,
        bool $hasConflict,
        ?string $conflictReason,
    ): array {
        if ($hasConflict) {
            return [
                'status' => 'drift',
                'summary' => $conflictReason ?? 'Conflicting declarations prevent a stable effective policy outcome.',
                'driftReason' => $conflictReason,
                'missingCapabilities' => [],
                'recommendedActions' => ['Resolve conflicting requirement declarations before relying on this control.'],
            ];
        }

        return match (implode('|', [$domain, $control, $scope])) {
            'auth|login_throttle|ops-panel' => $this->verifyLoginThrottle($packages, $requestPackages, $effectiveLevel, $effectiveEnforcementMode),
            'auth|password_confirmation|destructive-settings' => $this->verifyPasswordConfirmation($packages, $requestPackages, $effectiveLevel, $effectiveEnforcementMode),
            'identity|privileged_mfa|super-admin' => $this->verifyPrivilegedMfa($packages, $requestPackages),
            default => [
                'status' => 'observed',
                'summary' => 'This control is declared and visible, but no runtime verification strategy is registered yet.',
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => [],
            ],
        };
    }

    /**
     * @param  array<int, string>  $packages
     * @param  array<int, string>  $requestPackages
     * @return array{status: string, summary: string, driftReason: string|null, missingCapabilities: array<int, string>, recommendedActions: array<int, string>}
     */
    private function verifyLoginThrottle(array $packages, array $requestPackages, string $effectiveLevel, string $effectiveEnforcementMode): array
    {
        if (! in_array('yezzmedia/laravel-ops', [...$packages, ...$requestPackages], true)) {
            return [
                'status' => 'observed',
                'summary' => 'The baseline login throttle policy is declared, but no ops producer declaration is currently loaded for runtime verification.',
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => [],
            ];
        }

        $missingCapabilities = [];

        if (! class_exists('YezzMedia\\Ops\\OpsPanelProvider')) {
            $missingCapabilities[] = 'ops-panel-provider';
        }

        if (! class_exists('Filament\\Auth\\Pages\\Login')) {
            $missingCapabilities[] = 'filament-login-page';
        }

        if (class_exists('Filament\\Auth\\Pages\\Login')
            && ! in_array('DanHarrin\\LivewireRateLimiting\\WithRateLimiting', class_uses_recursive('Filament\\Auth\\Pages\\Login'), true)) {
            $missingCapabilities[] = 'filament-login-rate-limiting';
        }

        if ($missingCapabilities !== []) {
            return [
                'status' => 'unmet',
                'summary' => 'The declared ops login throttle policy cannot currently be verified against the expected Filament login runtime.',
                'driftReason' => sprintf(
                    'Expected effective policy [%s/%s], but the ops login runtime is missing: %s.',
                    $effectiveLevel,
                    $effectiveEnforcementMode,
                    implode(', ', $missingCapabilities),
                ),
                'missingCapabilities' => $missingCapabilities,
                'recommendedActions' => [
                    'Ensure the ops panel keeps the Filament login page enabled for operator authentication.',
                    'Keep Filament login rate limiting available for the ops panel runtime.',
                ],
            ];
        }

        return [
            'status' => 'verified',
            'summary' => 'The ops panel exposes Filament login and the active Filament login page includes built-in rate limiting.',
            'driftReason' => null,
            'missingCapabilities' => [],
            'recommendedActions' => [],
        ];
    }

    /**
     * @param  array<int, string>  $packages
     * @param  array<int, string>  $requestPackages
     * @return array{status: string, summary: string, driftReason: string|null, missingCapabilities: array<int, string>, recommendedActions: array<int, string>}
     */
    private function verifyPasswordConfirmation(array $packages, array $requestPackages, string $effectiveLevel, string $effectiveEnforcementMode): array
    {
        if (! in_array('yezzmedia/laravel-ops-settings', [...$packages, ...$requestPackages], true)) {
            return [
                'status' => 'observed',
                'summary' => 'The password confirmation policy is declared, but no ops-settings producer declaration is currently loaded for runtime verification.',
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => [],
            ];
        }

        $missingCapabilities = [];
        $pageClass = 'YezzMedia\\OpsSettings\\Filament\\Pages\\OpsSettingsPage';

        if (! class_exists($pageClass)) {
            $missingCapabilities[] = 'ops-settings-page';
        } else {
            foreach (['confirmPassword', 'saveIdentity', 'applyPreset', 'importSnapshot'] as $method) {
                if (! method_exists($pageClass, $method)) {
                    $missingCapabilities[] = 'method:'.$method;
                }
            }
        }

        if ((int) config('ops-settings.security.password_confirmation.timeout', 0) <= 0) {
            $missingCapabilities[] = 'password-confirmation-timeout';
        }

        if ($missingCapabilities !== []) {
            return [
                'status' => 'drift',
                'summary' => 'The destructive settings confirmation policy is declared, but the ops-settings runtime does not expose all expected confirmation hooks yet.',
                'driftReason' => sprintf(
                    'Expected effective policy [%s/%s], but the ops-settings mutation runtime is missing: %s.',
                    $effectiveLevel,
                    $effectiveEnforcementMode,
                    implode(', ', $missingCapabilities),
                ),
                'missingCapabilities' => $missingCapabilities,
                'recommendedActions' => [
                    'Keep package-owned password confirmation wired directly into destructive ops-settings actions.',
                    'Configure a positive password confirmation timeout for the ops-settings workspace.',
                ],
            ];
        }

        return [
            'status' => 'verified',
            'summary' => 'The ops-settings workspace exposes package-owned password confirmation hooks for destructive settings mutations.',
            'driftReason' => null,
            'missingCapabilities' => [],
            'recommendedActions' => [],
        ];
    }

    /**
     * @param  array<int, string>  $packages
     * @param  array<int, string>  $requestPackages
     * @return array{status: string, summary: string, driftReason: string|null, missingCapabilities: array<int, string>, recommendedActions: array<int, string>}
     */
    private function verifyPrivilegedMfa(array $packages, array $requestPackages): array
    {
        if (! in_array('yezzmedia/laravel-access', [...$packages, ...$requestPackages], true)) {
            return [
                'status' => 'observed',
                'summary' => 'The privileged MFA policy is declared, but no access producer declaration is currently loaded for runtime verification.',
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => [],
            ];
        }

        if ($this->requestBroker instanceof DatabaseSecurityRequestBroker) {
            $counts = $this->requestBroker->visibilityCountsFor('privileged_mfa', 'super-admin');

            $runtimeEvidenceCount = $counts['runtimeEvidence'];
            $requestCount = $counts['requests'];
        } else {
            $records = $this->visibilityRecords();

            $runtimeEvidenceCount = count(array_filter(
                $records['runtimeEvidence'],
                static fn ($evidence): bool => $evidence->control === 'privileged_mfa' && $evidence->scope === 'super-admin',
            ));

            $requestCount = count(array_filter(
                $records['requests'],
                static fn ($request): bool => $request->control === 'privileged_mfa' && $request->scope === 'super-admin',
            ));
        }

        if ($runtimeEvidenceCount > 0) {
            return [
                'status' => 'verified',
                'summary' => sprintf('Privileged MFA runtime evidence has been recorded %d time(s) for super-admin visibility.', $runtimeEvidenceCount),
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => [],
            ];
        }

        if ($requestCount > 0) {
            return [
                'status' => 'observed',
                'summary' => 'Privileged MFA requests are being submitted, but no runtime gate evidence has been recorded yet.',
                'driftReason' => null,
                'missingCapabilities' => [],
                'recommendedActions' => ['Exercise a super-admin gate path so privileged MFA runtime evidence is recorded.'],
            ];
        }

        return [
            'status' => 'observed',
            'summary' => 'The privileged MFA policy is declared, but no privileged-account runtime evidence has been recorded yet.',
            'driftReason' => null,
            'missingCapabilities' => [],
            'recommendedActions' => ['Bootstrap or exercise the privileged access flow so MFA visibility reporting can produce runtime evidence.'],
        ];
    }

    /**
     * @param  array<int, string>  $levels
     */
    private function resolveEffectiveLevel(array $levels): string
    {
        if (in_array('disallowed', $levels, true)) {
            return 'disallowed';
        }

        foreach (['required', 'recommended', 'optional'] as $level) {
            if (in_array($level, $levels, true)) {
                return $level;
            }
        }

        return 'optional';
    }

    /**
     * @param  array<int, string>  $enforcementModes
     */
    private function resolveEffectiveEnforcementMode(array $enforcementModes): string
    {
        foreach (['centrally_enforced', 'package_owned', 'observe_only'] as $mode) {
            if (in_array($mode, $enforcementModes, true)) {
                return $mode;
            }
        }

        return 'observe_only';
    }

    private function computeAndStore(): SecurityPostureSummary
    {
        if (! config('ops-security.enabled', true)) {
            $this->memo = new SecurityPostureSummary(
                status: SecurityPostureStatus::Unknown,
                domains: [],
                alerts: [],
                resolvedAt: CarbonImmutable::now(),
                resolverDurationMs: 0,
            );

            return $this->memo;
        }

        $startTime = hrtime(true);
        $domainResults = [];

        foreach ($this->resolvers as $resolver) {
            $domain = $resolver->domain();

            // Skip disabled domains
            if (! config($domain->configKey(), true)) {
                $domainResults[] = new DomainPostureResult(
                    domain: $domain,
                    status: SecurityPostureStatus::Unknown,
                    summary: "{$domain->label()} is disabled.",
                    items: [],
                    checkedAt: CarbonImmutable::now(),
                    durationMs: 0,
                );

                continue;
            }

            try {
                $domainResults[] = $resolver->resolve();
            } catch (\Throwable $e) {
                $domainResults[] = new DomainPostureResult(
                    domain: $domain,
                    status: SecurityPostureStatus::Unknown,
                    summary: "Resolver error: {$e->getMessage()}",
                    items: [],
                    checkedAt: CarbonImmutable::now(),
                    durationMs: 0,
                );
            }
        }

        $totalDurationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        $this->memo = $this->summaryBuilder->build($domainResults, $totalDurationMs);

        if ($this->cacheEnabled) {
            $this->resolveCache()->put(self::CACHE_KEY, $this->memo, $this->cacheTtl);
        }

        return $this->memo;
    }

    private function resolveCache(): CacheRepository
    {
        if ($this->cache === null) {
            $this->cache = $this->cacheFactory->store($this->cacheStore);
        }

        return $this->cache;
    }
}
