<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Audit;

use YezzMedia\OpsSecurity\Contracts\SecurityAuditWriter;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

final readonly class NullSecurityAuditWriter implements SecurityAuditWriter
{
    public function securityPostureRefreshed(SecurityPostureRefreshed $event): void
    {
        // No-op
    }
}
