<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Listeners;

use YezzMedia\OpsSecurity\Contracts\SecurityAuditWriter;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

final readonly class WriteSecurityAuditEntry
{
    public function __construct(
        private SecurityAuditWriter $writer,
    ) {}

    public function handlePostureRefreshed(SecurityPostureRefreshed $event): void
    {
        $this->writer->securityPostureRefreshed($event);
    }
}
