<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecretHealthResult
{
    /**
     * @param  array<SecretCheckItem>  $items
     */
    public function __construct(
        public SecurityPostureStatus $status,
        public array $items,
        public int $totalChecked,
        public int $healthyCount,
        public int $warningCount,
        public int $criticalCount,
    ) {}
}
