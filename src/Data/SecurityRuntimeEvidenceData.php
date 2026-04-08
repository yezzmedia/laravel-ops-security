<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use Carbon\CarbonImmutable;

final readonly class SecurityRuntimeEvidenceData
{
    /**
     * @param  array<string, scalar|null>  $payloadPreview
     */
    public function __construct(
        public string $requestKey,
        public string $package,
        public string $domain,
        public string $control,
        public string $scope,
        public string $status,
        public array $payloadPreview,
        public ?string $source,
        public ?string $actor,
        public CarbonImmutable $recordedAt,
    ) {}
}
