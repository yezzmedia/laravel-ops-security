<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class SecretHealthCheck implements DoctorCheck
{
    private const KEY = 'ops-security.secret-health';

    private const PACKAGE = 'yezzmedia/laravel-ops-security';

    public function __construct(
        private OpsSecurityManager $manager,
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
        $result = $this->manager->domain(SecurityDomain::Secret);

        if ($result->status === SecurityPostureStatus::Critical) {
            // List critical secret names — never values
            $criticalNames = [];
            foreach ($result->items as $item) {
                if ($item->status === SecurityPostureStatus::Critical) {
                    $criticalNames[] = $item->name;
                }
            }

            return $this->result(
                'failed',
                'Critical secret health findings: '.implode(', ', $criticalNames),
                true,
                ['critical_secrets' => $criticalNames],
            );
        }

        return match ($result->status) {
            SecurityPostureStatus::Healthy => $this->result('passed', "Secret health: {$result->summary}", true),
            SecurityPostureStatus::Warning => $this->result('warning', "Secret health warning: {$result->summary}", true),
            SecurityPostureStatus::Unknown => $this->result('warning', "Secret health unknown: {$result->summary}", true),
            SecurityPostureStatus::Critical => $this->result('failed', "Secret health critical: {$result->summary}", true),
        };
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
