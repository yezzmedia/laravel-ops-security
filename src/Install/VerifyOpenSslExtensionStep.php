<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Install;

use YezzMedia\Foundation\Data\InstallContext;
use YezzMedia\Foundation\Install\InstallStep;

final readonly class VerifyOpenSslExtensionStep implements InstallStep
{
    private const KEY = 'ops-security.verify-openssl';

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
        return 5;
    }

    public function shouldRun(InstallContext $context): bool
    {
        return true;
    }

    public function handle(InstallContext $context): void
    {
        if (! extension_loaded('openssl')) {
            throw new \RuntimeException(
                'The openssl PHP extension is required for SSL posture checking. Install it with: sudo apt-get install php-openssl'
            );
        }
    }
}
