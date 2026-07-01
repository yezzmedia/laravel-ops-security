<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Install;

use YezzMedia\Foundation\Data\InstallContext;
use YezzMedia\Foundation\Install\InstallStep;
use YezzMedia\Foundation\Install\OptionalInstallStep;
use YezzMedia\OpsSecurity\Support\OpsSecurityVisibilityStoreSetup;

final class EnsureOpsSecurityVisibilityStoreReadyInstallStep implements InstallStep, OptionalInstallStep
{
    public function __construct(private readonly OpsSecurityVisibilityStoreSetup $setup) {}

    public function key(): string
    {
        return 'ensure_ops_security_visibility_store_ready';
    }

    public function package(): string
    {
        return 'yezzmedia/laravel-ops-security';
    }

    public function priority(): int
    {
        return 20;
    }

    public function shouldRun(InstallContext $context): bool
    {
        return ! $this->setup->storeReady();
    }

    public function handle(InstallContext $context): void
    {
        if ($this->setup->hasPartialTables()) {
            fwrite(
                STDERR,
                "\n  \033[33;1mWARNING\033[39;22m  The ops-security visibility store is only partially installed. "
                .'Repair the database state before rerunning the install flow.'."\n\n"
            );

            return;
        }

        if (! $context->allowMigrations) {
            fwrite(
                STDERR,
                "\n  \033[33;1mWARNING\033[39;22m  The ops-security visibility store is not ready. "
                .'Run `php artisan migrate` or rerun the install command with `--migrate`.'."\n\n"
            );

            return;
        }

        $this->setup->runMigrations();

        if (! $this->setup->storeReady()) {
            fwrite(
                STDERR,
                "\n  \033[33;1mWARNING\033[39;22m  The ops-security visibility store is still not ready after running migrations.\n\n"
            );
        }
    }

    public function isOptional(): bool
    {
        return true;
    }
}
