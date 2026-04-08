<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class DomainPostureResult
{
    /**
     * @param  array<mixed>  $items  Domain-specific items (CertificatePosture[], SshKeyInfo[], SecretCheckItem[], SecurityConfigItem[]).
     */
    public function __construct(
        public SecurityDomain $domain,
        public SecurityPostureStatus $status,
        public string $summary,
        public array $items,
        public CarbonImmutable $checkedAt,
        public int $durationMs,
    ) {}
}
