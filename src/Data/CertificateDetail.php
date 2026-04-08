<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;

final readonly class CertificateDetail
{
    /**
     * @param  array<string>  $subjectAlternativeNames
     */
    public function __construct(
        public string $subject,
        public string $issuer,
        public CarbonImmutable $validFrom,
        public CarbonImmutable $validTo,
        public int $daysUntilExpiry,
        public string $serialNumber,
        public string $signatureAlgorithm,
        public ?string $tlsVersion,
        public bool $isWildcard,
        public array $subjectAlternativeNames,
        public bool $isSelfSigned,
        public bool $chainComplete,
    ) {}
}
