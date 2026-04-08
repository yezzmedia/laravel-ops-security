<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use YezzMedia\OpsSecurity\Actions\RefreshSecurityPostureAction;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

it('dispatches SecurityPostureRefreshed event on refresh', function (): void {
    Event::fake([SecurityPostureRefreshed::class]);

    $action = app(RefreshSecurityPostureAction::class);
    $summary = $action->execute('test');

    expect($summary->status)->toBeInstanceOf(SecurityPostureStatus::class);

    Event::assertDispatched(SecurityPostureRefreshed::class, function (SecurityPostureRefreshed $event): bool {
        return $event->triggeredBy === 'test'
            && $event->status instanceof SecurityPostureStatus
            && $event->resolvedAt instanceof CarbonImmutable;
    });
});

it('includes domain and alert counts in the event', function (): void {
    Event::fake([SecurityPostureRefreshed::class]);

    app(RefreshSecurityPostureAction::class)->execute('test');

    Event::assertDispatched(SecurityPostureRefreshed::class, function (SecurityPostureRefreshed $event): bool {
        return $event->alertCount >= 0
            && $event->criticalCount >= 0
            && $event->warningCount >= 0
            && $event->domainStatuses !== [];
    });
});
