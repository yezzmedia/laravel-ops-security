<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;

final readonly class SecurityGovernanceSummary
{
    /**
     * @param  array<string, array<int, SecurityRequestDefinition>>  $requestsByPackage
     * @param  array<string, array<int, SecurityRequirementDefinition>>  $requirementsByPackage
     * @param  array<int, EffectiveSecurityControl>  $effectiveControls
     * @param  array<int, string>  $remediationRecommendations
     */
    public function __construct(
        public array $requestsByPackage,
        public array $requirementsByPackage,
        public array $effectiveControls,
        public int $requestCount,
        public int $requirementCount,
        public int $packageCount,
        public int $conflictCount,
        public int $verifiedCount,
        public int $observedCount,
        public int $driftCount,
        public int $unmetCapabilityCount,
        public array $remediationRecommendations,
    ) {}
}
