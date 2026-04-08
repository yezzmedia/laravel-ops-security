<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use RuntimeException;
use YezzMedia\OpsSecurity\Data\SecretDefinition;
use YezzMedia\OpsSecurity\Enums\SecretCategory;

final class SecretDefinitionRegistry
{
    /** @var array<string, SecretDefinition> */
    private array $definitions = [];

    private bool $sealed = false;

    /**
     * Register a secret definition.
     *
     * @throws RuntimeException If the registry is sealed.
     */
    public function register(SecretDefinition $definition): void
    {
        if ($this->sealed) {
            throw new RuntimeException('SecretDefinitionRegistry is sealed. Late registrations are not allowed.');
        }

        $this->definitions[$definition->envKey] = $definition;
    }

    /**
     * Return all registered definitions.
     *
     * @return array<SecretDefinition>
     */
    public function all(): array
    {
        return array_values($this->definitions);
    }

    /**
     * Return definitions for a specific category.
     *
     * @return array<SecretDefinition>
     */
    public function forCategory(SecretCategory $category): array
    {
        return array_values(
            array_filter(
                $this->definitions,
                static fn (SecretDefinition $def): bool => $def->category === $category,
            )
        );
    }

    /**
     * Seal the registry. No further registrations are allowed.
     */
    public function seal(): void
    {
        $this->sealed = true;
    }

    /**
     * Whether the registry is sealed.
     */
    public function isSealed(): bool
    {
        return $this->sealed;
    }

    /**
     * Register the default set of Laravel secret definitions.
     */
    public function registerDefaults(int $minimumLength, float $minimumEntropy): void
    {
        $defaults = [
            new SecretDefinition('APP_KEY', 'APP_KEY', SecretCategory::Application, ['production', 'staging'], $minimumLength, $minimumEntropy),
            new SecretDefinition('APP_ENV', 'APP_ENV', SecretCategory::Application, ['production'], 0, 0.0),
            new SecretDefinition('DB_PASSWORD', 'DB_PASSWORD', SecretCategory::Database, ['production'], $minimumLength, $minimumEntropy),
            new SecretDefinition('DB_USERNAME', 'DB_USERNAME', SecretCategory::Database, ['production'], 4, 1.0),
            new SecretDefinition('MAIL_PASSWORD', 'MAIL_PASSWORD', SecretCategory::Mail, ['production'], $minimumLength, $minimumEntropy),
            new SecretDefinition('REDIS_PASSWORD', 'REDIS_PASSWORD', SecretCategory::Cache, ['production'], $minimumLength, $minimumEntropy),
            new SecretDefinition('MAIL_USERNAME', 'MAIL_USERNAME', SecretCategory::Mail, ['production'], 4, 1.0),
            new SecretDefinition('AWS_ACCESS_KEY_ID', 'AWS_ACCESS_KEY_ID', SecretCategory::Api, ['production'], 16, 3.0),
            new SecretDefinition('AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_ACCESS_KEY', SecretCategory::Api, ['production'], 16, 3.0),
            new SecretDefinition('PUSHER_APP_SECRET', 'PUSHER_APP_SECRET', SecretCategory::Api, ['production'], 16, 3.0),
        ];

        foreach ($defaults as $definition) {
            if (! isset($this->definitions[$definition->envKey])) {
                $this->register($definition);
            }
        }
    }
}
