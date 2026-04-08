<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityConfigItem
{
    public function __construct(
        public string $key,
        public string $label,
        public SecurityPostureStatus $status,
        public string $currentState,
        public string $expectedState,
        public ?string $finding,
    ) {}
}
