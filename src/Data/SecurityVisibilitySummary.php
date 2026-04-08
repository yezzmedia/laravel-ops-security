<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

final readonly class SecurityVisibilitySummary
{
    /**
     * @param  array<int, SecurityRequestRecordData>  $requests
     * @param  array<int, SecurityDecisionRecordData>  $decisions
     * @param  array<int, SecurityRuntimeEvidenceData>  $runtimeEvidence
     */
    public function __construct(
        public array $requests,
        public array $decisions,
        public array $runtimeEvidence,
        public int $requestCount,
        public int $decisionCount,
        public int $runtimeEvidenceCount,
        public int $conflictDecisionCount,
        public int $requestDisplayCount,
        public int $decisionDisplayCount,
        public int $runtimeEvidenceDisplayCount,
    ) {}
}
