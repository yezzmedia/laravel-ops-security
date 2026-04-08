<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Data;

use YezzMedia\OpsSecurity\Enums\SecretCategory;

/**
 * Internal DTO for secret definitions used by the SecretDefinitionRegistry.
 */
final readonly class SecretDefinition
{
    /**
     * @param  array<string>  $requiredEnvironments
     * @param  array<string>  $knownDefaults
     */
    public function __construct(
        public string $name,
        public string $envKey,
        public SecretCategory $category,
        public array $requiredEnvironments = ['production'],
        public int $minimumLength = 16,
        public float $minimumEntropy = 3.0,
        public array $knownDefaults = [],
    ) {}
}
