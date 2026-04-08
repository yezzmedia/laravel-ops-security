<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Data\CertificatePosture;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\SecretCheckItem;
use YezzMedia\OpsSecurity\Data\SecurityAlert;
use YezzMedia\OpsSecurity\Data\SecurityConfigItem;
use YezzMedia\OpsSecurity\Data\SecurityPostureSummary;
use YezzMedia\OpsSecurity\Data\SshKeyInfo;
use YezzMedia\OpsSecurity\Enums\CertificateStatus;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;

final readonly class SecurityPostureSummaryBuilder
{
    /**
     * Aggregate domain results into a SecurityPostureSummary.
     *
     * @param  array<DomainPostureResult>  $domainResults
     */
    public function build(array $domainResults, int $totalDurationMs): SecurityPostureSummary
    {
        $domains = [];
        $statuses = [];
        $alerts = [];

        foreach ($domainResults as $result) {
            $domains[$result->domain->value] = $result;
            $statuses[] = $result->status;
            $alerts = array_merge($alerts, $this->generateAlerts($result));
        }

        // Sort alerts: Critical first, then Warning
        usort($alerts, static function (SecurityAlert $a, SecurityAlert $b): int {
            $priority = static fn (SecurityPostureStatus $s): int => match ($s) {
                SecurityPostureStatus::Critical => 0,
                SecurityPostureStatus::Warning => 1,
                default => 2,
            };

            return $priority($a->severity) <=> $priority($b->severity);
        });

        $overallStatus = SecurityPostureStatus::worstOf($statuses);

        return new SecurityPostureSummary(
            status: $overallStatus,
            domains: $domains,
            alerts: $alerts,
            resolvedAt: CarbonImmutable::now(),
            resolverDurationMs: $totalDurationMs,
        );
    }

    /**
     * Generate alerts from a domain result.
     *
     * @return array<SecurityAlert>
     */
    private function generateAlerts(DomainPostureResult $result): array
    {
        $alerts = [];

        foreach ($result->items as $item) {
            $alert = $this->itemToAlert($result->domain, $item);
            if ($alert !== null) {
                $alerts[] = $alert;
            }
        }

        return $alerts;
    }

    private function itemToAlert(SecurityDomain $domain, mixed $item): ?SecurityAlert
    {
        return match (true) {
            $item instanceof CertificatePosture => $this->certificateAlert($domain, $item),
            $item instanceof SshKeyInfo => $this->sshKeyAlert($domain, $item),
            $item instanceof SecretCheckItem => $this->secretAlert($domain, $item),
            $item instanceof SecurityConfigItem => $this->configAlert($domain, $item),
            default => null,
        };
    }

    private function certificateAlert(SecurityDomain $domain, CertificatePosture $cert): ?SecurityAlert
    {
        $postureStatus = $cert->status->toPostureStatus();

        if ($postureStatus === SecurityPostureStatus::Healthy) {
            return null;
        }

        $severity = $postureStatus === SecurityPostureStatus::Critical
            ? SecurityPostureStatus::Critical
            : SecurityPostureStatus::Warning;

        return new SecurityAlert(
            domain: $domain,
            severity: $severity,
            title: match ($cert->status) {
                CertificateStatus::Expired => "Certificate expired for {$cert->domain}",
                CertificateStatus::ExpiringSoon => "Certificate expiring soon for {$cert->domain}",
                CertificateStatus::Invalid => "Invalid certificate for {$cert->domain}",
                CertificateStatus::Unreachable => "Cannot reach {$cert->domain} for certificate check",
                default => "Certificate issue for {$cert->domain}",
            },
            description: $cert->error ?? "Certificate status is {$cert->status->label()} for {$cert->domain}.",
            recommendation: match ($cert->status) {
                CertificateStatus::Expired => "Renew the SSL certificate for {$cert->domain} immediately.",
                CertificateStatus::ExpiringSoon => "Schedule certificate renewal for {$cert->domain} before expiry.",
                CertificateStatus::Invalid => "Replace the invalid certificate for {$cert->domain} with a valid one.",
                CertificateStatus::Unreachable => "Verify network connectivity and DNS for {$cert->domain}.",
                default => "Investigate the certificate issue for {$cert->domain}.",
            },
        );
    }

    private function sshKeyAlert(SecurityDomain $domain, SshKeyInfo $key): ?SecurityAlert
    {
        if ($key->type->isDeprecated()) {
            return new SecurityAlert(
                domain: $domain,
                severity: SecurityPostureStatus::Warning,
                title: "Deprecated SSH key type: {$key->type->label()}",
                description: "SSH key {$key->filename} uses deprecated {$key->type->label()} algorithm.",
                recommendation: "Replace {$key->filename} with an Ed25519 or ECDSA key.",
            );
        }

        $maxAge = (int) config('ops-security.ssh.max_key_age_days', 365);
        if ($key->ageInDays !== null && $key->ageInDays > $maxAge) {
            return new SecurityAlert(
                domain: $domain,
                severity: SecurityPostureStatus::Warning,
                title: "SSH key {$key->filename} is {$key->ageInDays} days old",
                description: "SSH key {$key->filename} exceeds the maximum recommended age of {$maxAge} days.",
                recommendation: "Rotate SSH key {$key->filename} to a new key pair.",
            );
        }

        return null;
    }

    private function secretAlert(SecurityDomain $domain, SecretCheckItem $secret): ?SecurityAlert
    {
        if ($secret->status === SecurityPostureStatus::Healthy) {
            return null;
        }

        $severity = $secret->status === SecurityPostureStatus::Critical
            ? SecurityPostureStatus::Critical
            : SecurityPostureStatus::Warning;

        return new SecurityAlert(
            domain: $domain,
            severity: $severity,
            title: "Secret {$secret->name} issue",
            description: $secret->finding ?? "Secret {$secret->name} does not meet security requirements.",
            recommendation: match (true) {
                ! $secret->isPresent => "Set the {$secret->name} environment variable.",
                $secret->isDefault => "Rotate {$secret->name} to a strong random value.",
                ! $secret->meetsLengthThreshold => "Use a longer value for {$secret->name}.",
                ! $secret->meetsEntropyThreshold => "Use a more random value for {$secret->name}.",
                default => "Review the {$secret->name} configuration.",
            },
        );
    }

    private function configAlert(SecurityDomain $domain, SecurityConfigItem $item): ?SecurityAlert
    {
        if ($item->status === SecurityPostureStatus::Healthy) {
            return null;
        }

        $severity = $item->status === SecurityPostureStatus::Critical
            ? SecurityPostureStatus::Critical
            : SecurityPostureStatus::Warning;

        return new SecurityAlert(
            domain: $domain,
            severity: $severity,
            title: $item->label,
            description: $item->finding ?? "Configuration check '{$item->key}' is not in the expected state.",
            recommendation: "Change {$item->key} from '{$item->currentState}' to '{$item->expectedState}'.",
        );
    }
}
