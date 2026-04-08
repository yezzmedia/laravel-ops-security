<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

final readonly class EffectiveSecurityControl
{
    /**
     * @param  array<int, string>  $packages
     * @param  array<int, string>  $requirementKeys
     * @param  array<int, string>  $requestKeys
     * @param  array<int, string>  $requestPackages
     * @param  array<int, string>  $requestedLevels
     * @param  array<int, string>  $requestedEnforcementModes
     * @param  array<int, string>  $missingCapabilities
     * @param  array<int, string>  $recommendedActions
     */
    public function __construct(
        public string $domain,
        public string $control,
        public string $scope,
        public string $level,
        public string $enforcementMode,
        public array $packages,
        public array $requirementKeys,
        public array $requestKeys,
        public array $requestPackages,
        public array $requestedLevels,
        public array $requestedEnforcementModes,
        public string $verificationStatus = 'observed',
        public string $verificationSummary = 'No runtime verification has been recorded for this control yet.',
        public bool $hasConflict = false,
        public ?string $conflictReason = null,
        public ?string $driftReason = null,
        public array $missingCapabilities = [],
        public array $recommendedActions = [],
    ) {}
}
