<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Resolvers;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\SecretCheckItem;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Support\EntropyAnalyzer;
use YezzMedia\OpsSecurity\Support\SecretDefinitionRegistry;

final readonly class SecretHealthResolver implements SecurityPostureResolver
{
    public function __construct(
        private SecretDefinitionRegistry $registry,
        private EntropyAnalyzer $entropyAnalyzer,
    ) {}

    public function domain(): SecurityDomain
    {
        return SecurityDomain::Secret;
    }

    public function resolve(): DomainPostureResult
    {
        $startTime = hrtime(true);
        $checkedAt = CarbonImmutable::now();

        $definitions = $this->registry->all();
        $items = [];
        $environment = (string) config('app.env', 'production');
        $globalKnownDefaults = $this->getKnownDefaults();

        foreach ($definitions as $definition) {
            $value = env($definition->envKey);
            $stringValue = is_string($value) ? $value : (string) $value;

            // Check presence
            $isPresent = $value !== null && $value !== '';

            // Check if it matches a known default
            $allDefaults = array_merge($globalKnownDefaults, $definition->knownDefaults);
            $isDefault = $isPresent && in_array(strtolower($stringValue), array_map('strtolower', $allDefaults), true);

            // Check length threshold
            $meetsLengthThreshold = $isPresent && strlen($stringValue) >= $definition->minimumLength;

            // Check entropy threshold
            $meetsEntropyThreshold = $isPresent && $definition->minimumEntropy > 0.0
                && $this->entropyAnalyzer->meetsThreshold($stringValue, $definition->minimumEntropy);

            // Determine status based on environment
            $isRelevantEnvironment = in_array($environment, $definition->requiredEnvironments, true);
            $status = $this->determineStatus($isPresent, $isDefault, $meetsLengthThreshold, $meetsEntropyThreshold, $isRelevantEnvironment, $definition);
            $finding = $this->determineFinding($isPresent, $isDefault, $meetsLengthThreshold, $meetsEntropyThreshold, $isRelevantEnvironment, $definition->name);

            // Discard the secret value — never stored
            unset($value, $stringValue);

            $items[] = new SecretCheckItem(
                name: $definition->name,
                category: $definition->category,
                isPresent: $isPresent,
                isDefault: $isDefault,
                meetsLengthThreshold: $meetsLengthThreshold,
                meetsEntropyThreshold: $meetsEntropyThreshold,
                status: $status,
                finding: $finding,
            );
        }

        $statuses = array_map(static fn (SecretCheckItem $item): SecurityPostureStatus => $item->status, $items);
        $overallStatus = $statuses === [] ? SecurityPostureStatus::Healthy : SecurityPostureStatus::worstOf($statuses);

        $healthyCount = count(array_filter($items, static fn (SecretCheckItem $i): bool => $i->status === SecurityPostureStatus::Healthy));
        $warningCount = count(array_filter($items, static fn (SecretCheckItem $i): bool => $i->status === SecurityPostureStatus::Warning));
        $criticalCount = count(array_filter($items, static fn (SecretCheckItem $i): bool => $i->status === SecurityPostureStatus::Critical));

        $durationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        return new DomainPostureResult(
            domain: SecurityDomain::Secret,
            status: $overallStatus,
            summary: sprintf('%d secrets checked: %d healthy, %d warnings, %d critical.', count($items), $healthyCount, $warningCount, $criticalCount),
            items: $items,
            checkedAt: $checkedAt,
            durationMs: $durationMs,
        );
    }

    /**
     * @return array<string>
     */
    private function getKnownDefaults(): array
    {
        $configured = config('ops-security.secrets.known_defaults', []);
        $builtIn = ['password', 'secret', 'changeme', 'your-secret', 'example', 'your-api-key', 'test', ''];

        return array_unique(array_merge($builtIn, is_array($configured) ? $configured : []));
    }

    private function determineStatus(
        bool $isPresent,
        bool $isDefault,
        bool $meetsLengthThreshold,
        bool $meetsEntropyThreshold,
        bool $isRelevantEnvironment,
        mixed $definition,
    ): SecurityPostureStatus {
        if (! $isRelevantEnvironment) {
            // Non-relevant environments get a lighter check
            if (! $isPresent) {
                return SecurityPostureStatus::Warning;
            }

            return SecurityPostureStatus::Healthy;
        }

        if (! $isPresent) {
            return SecurityPostureStatus::Critical;
        }

        if ($isDefault) {
            return SecurityPostureStatus::Critical;
        }

        // APP_ENV only needs to be present and not a default
        if ($definition->minimumLength === 0 && $definition->minimumEntropy === 0.0) {
            return SecurityPostureStatus::Healthy;
        }

        if (! $meetsLengthThreshold || ! $meetsEntropyThreshold) {
            return SecurityPostureStatus::Warning;
        }

        return SecurityPostureStatus::Healthy;
    }

    private function determineFinding(
        bool $isPresent,
        bool $isDefault,
        bool $meetsLengthThreshold,
        bool $meetsEntropyThreshold,
        bool $isRelevantEnvironment,
        string $name,
    ): ?string {
        if (! $isRelevantEnvironment && ! $isPresent) {
            return "{$name} is not set (non-critical in this environment).";
        }

        if (! $isPresent) {
            return "{$name} is not set.";
        }

        if ($isDefault) {
            return 'Value matches known default placeholder.';
        }

        if (! $meetsLengthThreshold) {
            return 'Value does not meet minimum length requirement.';
        }

        if (! $meetsEntropyThreshold) {
            return 'Value does not meet minimum entropy requirement.';
        }

        return null;
    }
}
