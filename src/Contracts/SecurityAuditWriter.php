<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Contracts;

use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

interface SecurityAuditWriter
{
    /**
     * Write an audit entry for a security posture refresh.
     */
    public function securityPostureRefreshed(SecurityPostureRefreshed $event): void;
}
