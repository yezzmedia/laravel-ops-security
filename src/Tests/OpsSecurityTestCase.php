<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use YezzMedia\Foundation\Testing\FoundationTestCase;
use YezzMedia\OpsSecurity\OpsSecurityServiceProvider;

/**
 * Provides a realistic Testbench baseline for ops-security package tests.
 *
 * Sets up the in-memory SQLite database and registers the ops-security
 * service provider so that all package services are available during tests.
 */
abstract class OpsSecurityTestCase extends FoundationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->ensureVisibilityTablesExist();
    }

    protected function getPackageProviders($app): array
    {
        return [
            ...parent::getPackageProviders($app),
            OpsSecurityServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('ops-security.cache.enabled', false);
        $app['config']->set('ops-security.cache.store', null);
        $app['config']->set('ops-security.audit.driver', null);
    }

    private function ensureVisibilityTablesExist(): void
    {
        if (! Schema::hasTable('ops_security_requests')) {
            Schema::create('ops_security_requests', static function (Blueprint $table): void {
                $table->id();
                $table->string('request_key')->index();
                $table->string('package')->index();
                $table->string('domain')->index();
                $table->string('control')->index();
                $table->string('scope')->index();
                $table->string('requested_level');
                $table->string('requested_enforcement_mode');
                $table->string('status')->index();
                $table->json('payload_preview');
                $table->string('source')->nullable();
                $table->string('actor')->nullable();
                $table->timestamp('recorded_at')->index();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('ops_security_decisions')) {
            Schema::create('ops_security_decisions', static function (Blueprint $table): void {
                $table->id();
                $table->string('request_key')->index();
                $table->string('package')->index();
                $table->string('domain')->index();
                $table->string('control')->index();
                $table->string('scope')->index();
                $table->string('requested_level');
                $table->string('requested_enforcement_mode');
                $table->string('effective_level');
                $table->string('effective_enforcement_mode');
                $table->string('status')->index();
                $table->json('payload_preview');
                $table->boolean('has_conflict')->default(false)->index();
                $table->text('conflict_reason')->nullable();
                $table->string('source')->nullable();
                $table->string('actor')->nullable();
                $table->timestamp('recorded_at')->index();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('ops_security_runtime_evidence')) {
            Schema::create('ops_security_runtime_evidence', static function (Blueprint $table): void {
                $table->id();
                $table->string('request_key')->index();
                $table->string('package')->index();
                $table->string('domain')->index();
                $table->string('control')->index();
                $table->string('scope')->index();
                $table->string('status')->index();
                $table->json('payload_preview');
                $table->string('source')->nullable();
                $table->string('actor')->nullable();
                $table->timestamp('recorded_at')->index();
                $table->timestamps();
            });
        }
    }
}
