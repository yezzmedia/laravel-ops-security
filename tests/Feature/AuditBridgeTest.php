<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Spatie\Activitylog\Models\Activity;
use YezzMedia\OpsSecurity\Audit\ActivityLogSecurityAuditWriter;
use YezzMedia\OpsSecurity\Audit\NullSecurityAuditWriter;
use YezzMedia\OpsSecurity\Contracts\SecurityAuditWriter;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;

it('binds the null audit writer by default', function (): void {
    expect(config('ops-security.audit.driver'))->toBeNull();

    $writer = app(SecurityAuditWriter::class);

    expect($writer)->toBeInstanceOf(NullSecurityAuditWriter::class);
});

it('ships a null security audit driver by default in package config', function (): void {
    $config = require dirname(__DIR__, 2).'/config/ops-security.php';

    expect($config['audit']['driver'])->toBeNull();
});

it('null audit writer accepts events without error', function (): void {
    $writer = new NullSecurityAuditWriter;

    $writer->securityPostureRefreshed(new SecurityPostureRefreshed(
        status: SecurityPostureStatus::Healthy,
        domainStatuses: ['ssl' => 'healthy'],
        alertCount: 0,
        criticalCount: 0,
        warningCount: 0,
        resolvedAt: CarbonImmutable::parse('2026-04-07 12:00:00 UTC'),
        resolverDurationMs: 25,
        triggeredBy: 'test',
    ));

    expect(true)->toBeTrue();
});

it('binds the activitylog audit writer when the driver is enabled', function (): void {
    if (! class_exists(Activity::class)) {
        $this->markTestSkipped('spatie/laravel-activitylog is not installed in the package environment.');
    }

    if (! Schema::hasTable('activity_log')) {
        Schema::create('activity_log', static function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('log_name')->nullable();
            $table->text('description');
            $table->nullableMorphs('subject', 'subject');
            $table->nullableMorphs('causer', 'causer');
            $table->json('properties')->nullable();
            $table->string('event')->nullable();
            $table->json('attribute_changes')->nullable();
            $table->uuid('batch_uuid')->nullable();
            $table->timestamps();
            $table->index('log_name');
        });
    }

    config()->set('ops-security.audit.driver', 'activitylog');
    app()->forgetInstance(SecurityAuditWriter::class);

    $writer = app(SecurityAuditWriter::class);

    expect($writer)->toBeInstanceOf(ActivityLogSecurityAuditWriter::class);

    $writer->securityPostureRefreshed(new SecurityPostureRefreshed(
        status: SecurityPostureStatus::Warning,
        domainStatuses: ['ssl' => 'warning', 'ssh' => 'healthy'],
        alertCount: 2,
        criticalCount: 0,
        warningCount: 2,
        resolvedAt: CarbonImmutable::parse('2026-04-07 12:45:00 UTC'),
        resolverDurationMs: 140,
        triggeredBy: 'ops_panel',
    ));

    $activity = Activity::query()->latest('id')->first();

    expect($activity)->not->toBeNull()
        ->and($activity?->log_name)->toBe('ops-security')
        ->and($activity?->event)->toBe('security-posture-refreshed')
        ->and($activity?->description)->toBe('security-posture-refreshed')
        ->and($activity?->getProperty('status'))->toBe('warning')
        ->and($activity?->getProperty('domain_statuses'))->toBe(['ssl' => 'warning', 'ssh' => 'healthy'])
        ->and($activity?->getProperty('alert_count'))->toBe(2)
        ->and($activity?->getProperty('triggered_by'))->toBe('ops_panel');
});
