<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use YezzMedia\OpsSecurity\Data\SecurityPostureSummary;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class RefreshSecurityPostureAction
{
    public function __construct(
        private OpsSecurityManager $manager,
        private Dispatcher $events,
    ) {}

    public function execute(?string $source = null): SecurityPostureSummary
    {
        $summary = $this->manager->refresh();

        $domainStatuses = [];
        foreach ($summary->domains as $key => $domainResult) {
            $domainStatuses[$key] = $domainResult->status->value;
        }

        $criticalCount = count(array_filter($summary->alerts, static fn ($alert): bool => $alert->severity === SecurityPostureStatus::Critical));
        $warningCount = count(array_filter($summary->alerts, static fn ($alert): bool => $alert->severity === SecurityPostureStatus::Warning));

        $this->events->dispatch(new SecurityPostureRefreshed(
            status: $summary->status,
            domainStatuses: $domainStatuses,
            alertCount: count($summary->alerts),
            criticalCount: $criticalCount,
            warningCount: $warningCount,
            resolvedAt: $summary->resolvedAt,
            resolverDurationMs: $summary->resolverDurationMs,
            triggeredBy: $source,
        ));

        return $summary;
    }
}
