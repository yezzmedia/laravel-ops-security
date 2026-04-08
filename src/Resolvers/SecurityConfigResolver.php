<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Resolvers;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\SecurityConfigItem;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityConfigResolver implements SecurityPostureResolver
{
    public function domain(): SecurityDomain
    {
        return SecurityDomain::Config;
    }

    public function resolve(): DomainPostureResult
    {
        $startTime = hrtime(true);
        $checkedAt = CarbonImmutable::now();
        $environment = (string) config('app.env', 'production');

        $items = $this->runChecks($environment);

        $statuses = array_map(static fn (SecurityConfigItem $item): SecurityPostureStatus => $item->status, $items);
        $overallStatus = $statuses === [] ? SecurityPostureStatus::Healthy : SecurityPostureStatus::worstOf($statuses);

        $issueCount = count(array_filter($items, static fn (SecurityConfigItem $i): bool => $i->status !== SecurityPostureStatus::Healthy));
        $durationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        return new DomainPostureResult(
            domain: SecurityDomain::Config,
            status: $overallStatus,
            summary: sprintf('%d config checks, %d issues found.', count($items), $issueCount),
            items: $items,
            checkedAt: $checkedAt,
            durationMs: $durationMs,
        );
    }

    /**
     * @return array<SecurityConfigItem>
     */
    private function runChecks(string $environment): array
    {
        $isProduction = $environment === 'production';
        $productionOnly = (bool) config('ops-security.config.production_checks_only', false);

        $items = [];

        // Debug mode check
        $items[] = $this->checkDebugMode($isProduction);

        // APP_DEBUG check is critical in production
        if (! $productionOnly || $isProduction) {
            $items[] = $this->checkAppEnv($environment);
            $items[] = $this->checkSessionDriver();
            $items[] = $this->checkSessionLifetime();
            $items[] = $this->checkBcryptRounds();
            $items[] = $this->checkHttpsForcing();
        }

        return $items;
    }

    private function checkDebugMode(bool $isProduction): SecurityConfigItem
    {
        $debugEnabled = (bool) config('app.debug', false);

        if ($debugEnabled && $isProduction) {
            return new SecurityConfigItem(
                key: 'debug_mode',
                label: 'Debug Mode',
                status: SecurityPostureStatus::Critical,
                currentState: 'Enabled',
                expectedState: 'Disabled in production',
                finding: 'Debug mode is enabled in production. This exposes sensitive information.',
            );
        }

        if ($debugEnabled) {
            return new SecurityConfigItem(
                key: 'debug_mode',
                label: 'Debug Mode',
                status: SecurityPostureStatus::Warning,
                currentState: 'Enabled',
                expectedState: 'Disabled in production',
                finding: 'Debug mode is enabled. Ensure it is disabled before deploying to production.',
            );
        }

        return new SecurityConfigItem(
            key: 'debug_mode',
            label: 'Debug Mode',
            status: SecurityPostureStatus::Healthy,
            currentState: 'Disabled',
            expectedState: 'Disabled',
            finding: null,
        );
    }

    private function checkAppEnv(string $environment): SecurityConfigItem
    {
        $isProduction = $environment === 'production';

        return new SecurityConfigItem(
            key: 'app_env',
            label: 'Application Environment',
            status: SecurityPostureStatus::Healthy,
            currentState: $environment,
            expectedState: $isProduction ? 'production' : $environment,
            finding: null,
        );
    }

    private function checkSessionDriver(): SecurityConfigItem
    {
        $driver = (string) config('session.driver', 'file');
        $insecureDrivers = ['array'];

        if (in_array($driver, $insecureDrivers, true)) {
            return new SecurityConfigItem(
                key: 'session_driver',
                label: 'Session Driver',
                status: SecurityPostureStatus::Warning,
                currentState: $driver,
                expectedState: 'database, redis, or file',
                finding: "Session driver '{$driver}' does not persist sessions securely.",
            );
        }

        return new SecurityConfigItem(
            key: 'session_driver',
            label: 'Session Driver',
            status: SecurityPostureStatus::Healthy,
            currentState: $driver,
            expectedState: $driver,
            finding: null,
        );
    }

    private function checkSessionLifetime(): SecurityConfigItem
    {
        $lifetime = (int) config('session.lifetime', 120);
        $maxLifetime = (int) config('ops-security.config.session_max_lifetime', 480);

        if ($lifetime > $maxLifetime) {
            return new SecurityConfigItem(
                key: 'session_lifetime',
                label: 'Session Lifetime',
                status: SecurityPostureStatus::Warning,
                currentState: "{$lifetime} minutes",
                expectedState: "{$maxLifetime} minutes or less",
                finding: "Session lifetime of {$lifetime} minutes exceeds the recommended maximum of {$maxLifetime} minutes.",
            );
        }

        return new SecurityConfigItem(
            key: 'session_lifetime',
            label: 'Session Lifetime',
            status: SecurityPostureStatus::Healthy,
            currentState: "{$lifetime} minutes",
            expectedState: "{$maxLifetime} minutes or less",
            finding: null,
        );
    }

    private function checkBcryptRounds(): SecurityConfigItem
    {
        $rounds = (int) config('hashing.bcrypt.rounds', 12);
        $minimumRounds = (int) config('ops-security.config.minimum_bcrypt_rounds', 12);

        if ($rounds < $minimumRounds) {
            return new SecurityConfigItem(
                key: 'bcrypt_rounds',
                label: 'Bcrypt Rounds',
                status: SecurityPostureStatus::Warning,
                currentState: (string) $rounds,
                expectedState: "{$minimumRounds} or more",
                finding: "Bcrypt rounds ({$rounds}) is below the recommended minimum of {$minimumRounds}.",
            );
        }

        return new SecurityConfigItem(
            key: 'bcrypt_rounds',
            label: 'Bcrypt Rounds',
            status: SecurityPostureStatus::Healthy,
            currentState: (string) $rounds,
            expectedState: "{$minimumRounds} or more",
            finding: null,
        );
    }

    private function checkHttpsForcing(): SecurityConfigItem
    {
        $appUrl = (string) config('app.url', '');
        $isHttps = str_starts_with($appUrl, 'https://');

        if (! $isHttps) {
            return new SecurityConfigItem(
                key: 'https_forcing',
                label: 'HTTPS',
                status: SecurityPostureStatus::Warning,
                currentState: 'Not set',
                expectedState: 'APP_URL uses https://',
                finding: 'APP_URL does not use HTTPS.',
            );
        }

        return new SecurityConfigItem(
            key: 'https_forcing',
            label: 'HTTPS',
            status: SecurityPostureStatus::Healthy,
            currentState: 'Set',
            expectedState: 'APP_URL uses https://',
            finding: null,
        );
    }
}
