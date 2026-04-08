<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Doctor;

use YezzMedia\Foundation\Data\DoctorResult;
use YezzMedia\Foundation\Doctor\DoctorCheck;
use YezzMedia\OpsSecurity\OpsSecurityManager;

final readonly class SecurityDriftCheck implements DoctorCheck
{
    private const KEY = 'ops-security.governance-drift';

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

        if ($governance->driftCount === 0 && $governance->unmetCapabilityCount === 0) {
            return $this->result('passed', 'No active governance drift or unmet security capabilities were detected.', true, [
                'drift_count' => 0,
                'unmet_capability_count' => 0,
            ]);
        }

        return $this->result('failed', 'Security governance drift or missing runtime capabilities were detected.', true, [
            'drift_count' => $governance->driftCount,
            'unmet_capability_count' => $governance->unmetCapabilityCount,
            'remediation_recommendations' => $governance->remediationRecommendations,
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
