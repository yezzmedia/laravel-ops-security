<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Audit;

use Spatie\Activitylog\Support\ActivityLogger;
use YezzMedia\OpsSecurity\Contracts\SecurityAuditWriter;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

final readonly class ActivityLogSecurityAuditWriter implements SecurityAuditWriter
{
    public function __construct(
        private ActivityLogger $activityLogger,
    ) {}

    public function securityPostureRefreshed(SecurityPostureRefreshed $event): void
    {
        $this->activityLogger
            ->useLog('ops-security')
            ->event('security-posture-refreshed')
            ->withProperties([
                'status' => $event->status->value,
                'domain_statuses' => $event->domainStatuses,
                'alert_count' => $event->alertCount,
                'critical_count' => $event->criticalCount,
                'warning_count' => $event->warningCount,
                'triggered_by' => $event->triggeredBy,
                'resolver_duration_ms' => $event->resolverDurationMs,
            ])
            ->log('security-posture-refreshed');
    }
}
