<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Contracts;

use YezzMedia\OpsSecurity\Data\SecurityDecisionRecordData;
use YezzMedia\OpsSecurity\Data\SecurityRequestRecordData;
use YezzMedia\OpsSecurity\Data\SecurityRuntimeEvidenceData;

interface SecurityRequestBroker
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function submit(string $requestKey, array $payload = [], ?string $source = null, ?string $actor = null): SecurityDecisionRecordData;

    /**
     * @param  array<string, mixed>  $payload
     */
    public function recordRuntimeUsage(string $requestKey, array $payload = [], ?string $source = null, ?string $actor = null): SecurityRuntimeEvidenceData;

    /**
     * @return array<int, SecurityRequestRecordData>
     */
    public function requests(): array;

    /**
     * @return array<int, SecurityDecisionRecordData>
     */
    public function decisions(): array;

    /**
     * @return array<int, SecurityRuntimeEvidenceData>
     */
    public function runtimeEvidence(): array;
}
