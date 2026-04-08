<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityConfigResult
{
    /**
     * @param  array<SecurityConfigItem>  $items
     */
    public function __construct(
        public SecurityPostureStatus $status,
        public array $items,
        public string $environment,
        public CarbonImmutable $checkedAt,
    ) {}
}
