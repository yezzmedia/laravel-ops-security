<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use Illuminate\Contracts\Container\Container;
use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Resolvers\SecretHealthResolver;
use YezzMedia\OpsSecurity\Resolvers\SecurityConfigResolver;
use YezzMedia\OpsSecurity\Resolvers\SshPostureResolver;
use YezzMedia\OpsSecurity\Resolvers\SslPostureResolver;

final readonly class SecurityResolverCheck implements DoctorCheck
{
    private const KEY = 'ops-security.resolvers';

    private const PACKAGE = 'yezzmedia/laravel-ops-security';

    /** @var array<class-string<SecurityPostureResolver>> */
    private const RESOLVER_CLASSES = [
        SslPostureResolver::class,
        SshPostureResolver::class,
        SecretHealthResolver::class,
        SecurityConfigResolver::class,
    ];

    public function __construct(
        private Container $container,
    ) {}

    public function key(): string
    {
        return self::KEY;
    }

    public function package(): string
    {
        return self::PACKAGE;
    }

    public function run(): DoctorResult
    {
        $failures = [];

        foreach (self::RESOLVER_CLASSES as $resolverClass) {
            try {
                $resolver = $this->container->make($resolverClass);

                if (! $resolver instanceof SecurityPostureResolver) {
                    $failures[] = "{$resolverClass} does not implement SecurityPostureResolver.";
                }
            } catch (\Throwable $e) {
                $failures[] = "{$resolverClass}: {$e->getMessage()}";
            }
        }

        if ($failures !== []) {
            return $this->result(
                'failed',
                'Resolver check failed: '.implode('; ', $failures),
                true,
                ['failures' => $failures],
            );
        }

        return $this->result('passed', 'All 4 security posture resolvers are bound and instantiable.', true);
    }

    /**
     * @param  array<string, mixed>|null  $context
     */
    private function result(string $status, string $message, bool $isBlocking, ?array $context = null): DoctorResult
    {
        return new DoctorResult(
            key: self::KEY,
            package: self::PACKAGE,
            status: $status,
            message: $message,
            isBlocking: $isBlocking,
            context: $context,
        );
    }
}
