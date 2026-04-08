<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Events;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final class SecurityPostureRefreshed
{
    /**
     * @param  array<string, string>  $domainStatuses  Per-domain status values keyed by domain enum value.
     */
    public function __construct(
        public readonly SecurityPostureStatus $status,
        public readonly array $domainStatuses,
        public readonly int $alertCount,
        public readonly int $criticalCount,
        public readonly int $warningCount,
        public readonly CarbonImmutable $resolvedAt,
        public readonly int $resolverDurationMs,
        public readonly ?string $triggeredBy,
    ) {}
}
