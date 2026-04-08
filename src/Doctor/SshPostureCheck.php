<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class SshPostureCheck implements DoctorCheck
{
    private const KEY = 'ops-security.ssh-posture';

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
        $result = $this->manager->domain(SecurityDomain::Ssh);

        return match ($result->status) {
            SecurityPostureStatus::Healthy => $this->result('passed', 'SSH posture is healthy.', false),
            SecurityPostureStatus::Warning => $this->result('warning', "SSH posture warning: {$result->summary}", false),
            SecurityPostureStatus::Critical => $this->result('failed', "SSH posture critical: {$result->summary}", false),
            SecurityPostureStatus::Unknown => $this->result('warning', "SSH posture unknown: {$result->summary}", false),
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
