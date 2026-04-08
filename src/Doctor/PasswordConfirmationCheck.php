<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class PasswordConfirmationCheck implements DoctorCheck
{
    private const KEY = 'ops-security.password-confirmation';

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
        $control = $this->manager->governanceControl('auth', 'password_confirmation', 'destructive-settings');

        if ($control === null) {
            return $this->result('skipped', 'No destructive settings password confirmation control is currently registered.', false);
        }

        return match ($control->verificationStatus) {
            'verified' => $this->result('passed', $control->verificationSummary, true),
            'drift', 'unmet' => $this->result('failed', $control->driftReason ?? $control->verificationSummary, true, [
                'missing_capabilities' => $control->missingCapabilities,
            ]),
            default => $this->result('warning', $control->verificationSummary, true),
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
