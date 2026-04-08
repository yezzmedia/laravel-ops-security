<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecretCategory;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecretCheckItem
{
    public function __construct(
        public string $name,
        public SecretCategory $category,
        public bool $isPresent,
        public bool $isDefault,
        public bool $meetsLengthThreshold,
        public bool $meetsEntropyThreshold,
        public SecurityPostureStatus $status,
        public ?string $finding,
    ) {}
}
