<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class PrivilegedMfaCheck implements DoctorCheck
{
    private const KEY = 'ops-security.privileged-mfa';

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
        $control = $this->manager->governanceControl('identity', 'privileged_mfa', 'super-admin');

        if ($control === null) {
            return $this->result('skipped', 'No privileged MFA governance control is currently registered.', false);
        }

        return match ($control->verificationStatus) {
            'verified' => $this->result('passed', $control->verificationSummary, false),
            'drift', 'unmet' => $this->result('warning', $control->driftReason ?? $control->verificationSummary, false, [
                'missing_capabilities' => $control->missingCapabilities,
            ]),
            default => $this->result('warning', $control->verificationSummary, false),
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
