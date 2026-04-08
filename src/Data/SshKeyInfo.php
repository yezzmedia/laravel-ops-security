<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SshKeyType;

final readonly class SshKeyInfo
{
    public function __construct(
        public SshKeyType $type,
        public string $filename,
        public ?int $bitLength,
        public ?int $ageInDays,
        public bool $isPublicKeyOnly,
    ) {}
}
