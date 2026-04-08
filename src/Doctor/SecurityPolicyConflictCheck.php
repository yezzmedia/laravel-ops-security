<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class SecurityPolicyConflictCheck implements DoctorCheck
{
    private const KEY = 'ops-security.policy-conflicts';

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
        $governance = $this->manager->governance();

        if ($governance->conflictCount === 0) {
            return $this->result('passed', 'No conflicting security requirement declarations were detected.', true, [
                'conflict_count' => 0,
            ]);
        }

        return $this->result('failed', 'Conflicting security declarations were detected in the effective governance policy.', true, [
            'conflict_count' => $governance->conflictCount,
        ]);
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
