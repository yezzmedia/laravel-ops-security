<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class OpsSecurityVisibilityStoreSetup
{
    /** @var array<string, bool>|null */
    private ?array $visibilityTables = null;

    private ?bool $migrationsTableExistsMemo = null;

    /**
     * @var array<int, string>|null
     */
    private ?array $appliedMigrationNamesMemo = null;

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
        $paths = $this->pendingMigrationPaths();

        foreach ($paths as $path) {
            Artisan::call('migrate', [
                '--force' => true,
                '--path' => $path,
            ]);
        }

        $this->forgetVisibilityTables();
        $this->migrationsTableExistsMemo = null;
        $this->appliedMigrationNamesMemo = null;
    }

    public function forgetVisibilityTables(): void
    {
        $this->visibilityTables = null;
    }

    /**
     * @return array<int, string>
     */
    private function publishableMigrationNames(): array
    {
        return [
            'create_ops_security_visibility_tables',
        ];
    }

    /**
     * @return array<int, string>
     */
    private function pendingMigrationPaths(): array
    {
        $paths = [];
        $publishedPath = database_path('migrations');

        $applied = $this->migrationsTableExists()
            ? $this->appliedMigrationNames(migrationsTableExists: true)
            : [];

        foreach ($this->publishableMigrationNames() as $name) {
            $matches = glob($publishedPath.'/*_'.$name.'.php');

            if (empty($matches)) {
                continue;
            }

            $migrationKey = basename($matches[0], '.php');

            if (! in_array($migrationKey, $applied, true)) {
                $paths[] = str_replace(base_path().'/', '', $matches[0]);
            }
        }

        return $paths;
    }

    private function migrationsTableExists(): bool
    {
        return $this->migrationsTableExistsMemo ??= Schema::hasTable('migrations');
    }

    /**
     * @return array<int, string>
     */
    private function appliedMigrationNames(bool $migrationsTableExists = false): array
    {
        if ($this->appliedMigrationNamesMemo !== null) {
            return $this->appliedMigrationNamesMemo;
        }

        if (! $migrationsTableExists && ! $this->migrationsTableExists()) {
            return $this->appliedMigrationNamesMemo = [];
        }

        return $this->appliedMigrationNamesMemo = DB::table('migrations')
            ->pluck('migration')
            ->toArray();
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
