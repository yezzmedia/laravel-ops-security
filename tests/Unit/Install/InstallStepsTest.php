<?php

declare(strict_types=1);

use YezzMedia\Foundation\Data\InstallContext;
use YezzMedia\OpsSecurity\Install\EnsureOpsSecurityVisibilityStoreReadyInstallStep;
use YezzMedia\OpsSecurity\Support\OpsSecurityVisibilityStoreSetup;

function fakeOpsSecurityVisibilityStoreSetup(
    bool $ready = false,
    bool $partial = false,
    bool $migrationSucceeds = true,
): OpsSecurityVisibilityStoreSetup {
    return new class($ready, $partial, $migrationSucceeds) extends OpsSecurityVisibilityStoreSetup
    {
        /** @var array<int, string> */
        public array $calls = [];

        public function __construct(
            private bool $ready,
            private bool $partial,
            private bool $migrationSucceeds,
        ) {}

        public function hasPartialTables(): bool
        {
            return $this->partial;
        }

        public function storeReady(): bool
        {
            return $this->ready;
        }

        public function runMigrations(): void
        {
            $this->calls[] = 'run_migrations';

            if ($this->migrationSucceeds) {
                $this->ready = true;
                $this->partial = false;
            }
        }
    };
}

it('forgets cached visibility tables after running migrations', function (): void {
    $setup = new class extends OpsSecurityVisibilityStoreSetup
    {
        protected function callMigrations(): void {}
    };

    $reflection = new ReflectionClass(OpsSecurityVisibilityStoreSetup::class);
    $property = $reflection->getProperty('visibilityTables');
    $property->setAccessible(true);
    $property->setValue($setup, [
        'ops_security_requests' => false,
        'ops_security_decisions' => false,
        'ops_security_runtime_evidence' => false,
    ]);

    $setup->runMigrations();

    expect($property->getValue($setup))->toBeNull();
});

it('returns without throwing when migration permission is not granted before ensuring the visibility store', function (): void {
    $setup = fakeOpsSecurityVisibilityStoreSetup(ready: false);
    $step = new EnsureOpsSecurityVisibilityStoreReadyInstallStep($setup);

    expect(fn () => $step->handle(new InstallContext))
        ->not->toThrow(RuntimeException::class);
});

it('runs migrations when the visibility store is not ready and migrations are allowed', function (): void {
    $setup = fakeOpsSecurityVisibilityStoreSetup(ready: false);
    $step = new EnsureOpsSecurityVisibilityStoreReadyInstallStep($setup);

    $step->handle(new InstallContext(allowMigrations: true));

    expect($setup->calls)->toBe(['run_migrations'])
        ->and($setup->storeReady())->toBeTrue();
});

it('returns without throwing for partially installed visibility tables', function (): void {
    $setup = fakeOpsSecurityVisibilityStoreSetup(ready: false, partial: true);
    $step = new EnsureOpsSecurityVisibilityStoreReadyInstallStep($setup);

    expect(fn () => $step->handle(new InstallContext(allowMigrations: true)))
        ->not->toThrow(RuntimeException::class);
});

it('skips the ensure step when the visibility store is already ready', function (): void {
    $setup = fakeOpsSecurityVisibilityStoreSetup(ready: true);
    $step = new EnsureOpsSecurityVisibilityStoreReadyInstallStep($setup);

    expect($step->shouldRun(new InstallContext))->toBeFalse();
});
