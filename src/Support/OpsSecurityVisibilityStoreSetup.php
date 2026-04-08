<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;

class OpsSecurityVisibilityStoreSetup
{
    /** @var array<string, bool>|null */
    private ?array $visibilityTables = null;

    /**
     * @return array<int, string>
     */
    public function missingTables(): array
    {
        return array_keys(array_filter(
            $this->visibilityTables(),
            static fn (bool $exists): bool => $exists === false,
        ));
    }

    public function hasPartialTables(): bool
    {
        $tables = $this->visibilityTables();

        return in_array(true, $tables, true) && in_array(false, $tables, true);
    }

    public function storeReady(): bool
    {
        return $this->missingTables() === [];
    }

    public function runMigrations(): void
    {
        Artisan::call('migrate', [
            '--path' => $this->migrationPath(),
            '--realpath' => true,
            '--force' => true,
        ]);
    }

    /**
     * @return array<string, bool>
     */
    private function visibilityTables(): array
    {
        if ($this->visibilityTables !== null) {
            return $this->visibilityTables;
        }

        return $this->visibilityTables = [
            'ops_security_requests' => Schema::hasTable('ops_security_requests'),
            'ops_security_decisions' => Schema::hasTable('ops_security_decisions'),
            'ops_security_runtime_evidence' => Schema::hasTable('ops_security_runtime_evidence'),
        ];
    }

    private function migrationPath(): string
    {
        return dirname(__DIR__, 2).'/database/migrations';
    }
}
