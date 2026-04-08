<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityPostureSummary
{
    /**
     * @param  array<string, DomainPostureResult>  $domains  Keyed by SecurityDomain->value.
     * @param  array<SecurityAlert>  $alerts  Sorted by severity (critical first).
     */
    public function __construct(
        public SecurityPostureStatus $status,
        public array $domains,
        public array $alerts,
        public CarbonImmutable $resolvedAt,
        public int $resolverDurationMs,
    ) {}
}
