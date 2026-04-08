<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class SecurityConfigCheck implements DoctorCheck
{
    private const KEY = 'ops-security.security-config';

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
        $result = $this->manager->domain(SecurityDomain::Config);

        if ($result->status === SecurityPostureStatus::Critical) {
            $criticalItems = [];
            foreach ($result->items as $item) {
                if ($item->status === SecurityPostureStatus::Critical) {
                    $criticalItems[] = $item->label;
                }
            }

            return $this->result(
                'failed',
                'Critical security config findings: '.implode(', ', $criticalItems),
                true,
                ['critical_items' => $criticalItems],
            );
        }

        return match ($result->status) {
            SecurityPostureStatus::Healthy => $this->result('passed', "Security configuration: {$result->summary}", true),
            SecurityPostureStatus::Warning => $this->result('warning', "Security configuration warning: {$result->summary}", true),
            SecurityPostureStatus::Unknown => $this->result('warning', "Security configuration unknown: {$result->summary}", true),
            SecurityPostureStatus::Critical => $this->result('failed', "Security configuration critical: {$result->summary}", true),
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
