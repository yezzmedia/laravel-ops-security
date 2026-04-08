<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityAlert
{
    public function __construct(
        public SecurityDomain $domain,
        public SecurityPostureStatus $severity,
        public string $title,
        public string $description,
        public string $recommendation,
    ) {}
}
