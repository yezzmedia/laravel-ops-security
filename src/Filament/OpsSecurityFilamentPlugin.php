<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Filament;

use Filament\Contracts\Plugin;
use Filament\Panel;
use YezzMedia\OpsSecurity\Filament\Pages\OpsSecurityPage;

/**
 * Registers the Ops Security UI pages into a Filament panel.
 */
final class OpsSecurityFilamentPlugin implements Plugin
{
    public static function make(): static
    {
        return new self;
    }

    public function getId(): string
    {
        return 'ops-security';
    }

    public function register(Panel $panel): void
    {
        $panel->pages([
            OpsSecurityPage::class,
        ]);
    }

    public function boot(Panel $panel): void {}
}
