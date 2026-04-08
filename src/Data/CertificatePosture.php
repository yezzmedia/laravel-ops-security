<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Enums\CertificateStatus;

final readonly class CertificatePosture
{
    public function __construct(
        public string $domain,
        public CertificateStatus $status,
        public ?CertificateDetail $certificate,
        public ?string $error,
        public CarbonImmutable $checkedAt,
    ) {}
}
