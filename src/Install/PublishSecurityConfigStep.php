<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Install;

use YezzMedia\Foundation\Data\InstallContext;
use YezzMedia\Foundation\Install\InstallStep;

final readonly class PublishSecurityConfigStep implements InstallStep
{
    private const KEY = 'ops-security.publish-config';

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
        return 100;
    }

    public function shouldRun(InstallContext $context): bool
    {
        if ($context->refreshPublishedResources) {
            return true;
        }

        return ! file_exists(config_path('ops-security.php'));
    }

    public function handle(InstallContext $context): void
    {
        $source = dirname(__DIR__, 2).'/config/ops-security.php';
        $destination = config_path('ops-security.php');

        if (! file_exists($destination)) {
            copy($source, $destination);
        }
    }
}
