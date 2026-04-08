<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Install;

use YezzMedia\Foundation\Data\InstallContext;
use YezzMedia\Foundation\Install\InstallStep;

final readonly class VerifyOpsDependencyStep implements InstallStep
{
    private const KEY = 'ops-security.verify-ops-dependency';

    private const PACKAGE = 'yezzmedia/laravel-ops-security';

    public function key(): string
    {
        return self::KEY;
    }

    public function package(): string
    {
        return self::PACKAGE;
    }

    public function priority(): int
    {
        return 10;
    }

    public function shouldRun(InstallContext $context): bool
    {
        return true;
    }

    public function handle(InstallContext $context): void
    {
        if (! class_exists('YezzMedia\\Ops\\OpsServiceProvider')) {
            throw new \RuntimeException(
                'yezzmedia/laravel-ops is not installed. Run: composer require yezzmedia/laravel-ops'
            );
        }
    }
}
