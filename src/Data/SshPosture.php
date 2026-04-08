<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SshPosture
{
    /**
     * @param  array<SshKeyInfo>  $keys
     * @param  array<string>  $configFindings
     */
    public function __construct(
        public SecurityPostureStatus $status,
        public array $keys,
        public int $authorizedKeyCount,
        public array $configFindings,
        public ?string $error,
    ) {}
}
