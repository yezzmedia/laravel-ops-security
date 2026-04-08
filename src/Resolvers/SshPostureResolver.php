<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Resolvers;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\SshKeyInfo;
use YezzMedia\OpsSecurity\Data\SshPosture;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Enums\SshKeyType;

final readonly class SshPostureResolver implements SecurityPostureResolver
{
    public function domain(): SecurityDomain
    {
        return SecurityDomain::Ssh;
    }

    public function resolve(): DomainPostureResult
    {
        $startTime = hrtime(true);
        $checkedAt = CarbonImmutable::now();

        $sshDir = $this->getSshDirectory();
        $configPath = $this->getSshConfigPath();

        if (! is_dir($sshDir) || ! is_readable($sshDir)) {
            $posture = new SshPosture(
                status: SecurityPostureStatus::Unknown,
                keys: [],
                authorizedKeyCount: 0,
                configFindings: [],
                error: "SSH directory {$sshDir} does not exist or is not readable.",
            );

            $durationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

            return new DomainPostureResult(
                domain: SecurityDomain::Ssh,
                status: SecurityPostureStatus::Unknown,
                summary: 'SSH directory not accessible.',
                items: [],
                checkedAt: $checkedAt,
                durationMs: $durationMs,
            );
        }

        $keys = $this->discoverKeys($sshDir);
        $authorizedKeyCount = $this->countAuthorizedKeys($sshDir);
        $configFindings = $this->checkSshConfig($configPath);

        $statuses = [];
        $maxAge = (int) config('ops-security.ssh.max_key_age_days', 365);

        foreach ($keys as $key) {
            if ($key->type->isDeprecated()) {
                $statuses[] = SecurityPostureStatus::Warning;
            } elseif ($key->ageInDays !== null && $key->ageInDays > $maxAge) {
                $statuses[] = SecurityPostureStatus::Warning;
            } else {
                $statuses[] = SecurityPostureStatus::Healthy;
            }
        }

        if ($configFindings !== []) {
            $statuses[] = SecurityPostureStatus::Warning;
        }

        $overallStatus = $statuses === []
            ? SecurityPostureStatus::Healthy
            : SecurityPostureStatus::worstOf($statuses);

        $durationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        return new DomainPostureResult(
            domain: SecurityDomain::Ssh,
            status: $overallStatus,
            summary: sprintf('%d SSH keys found, %d authorized keys.', count($keys), $authorizedKeyCount),
            items: $keys,
            checkedAt: $checkedAt,
            durationMs: $durationMs,
        );
    }

    private function getSshDirectory(): string
    {
        return config('ops-security.ssh.key_directory')
            ?? ($_SERVER['HOME'] ?? '/root').'/.ssh';
    }

    private function getSshConfigPath(): string
    {
        return config('ops-security.ssh.config_path') ?? '/etc/ssh/sshd_config';
    }

    /**
     * @return array<SshKeyInfo>
     */
    private function discoverKeys(string $sshDir): array
    {
        $keys = [];
        $files = @scandir($sshDir);

        if ($files === false) {
            return [];
        }

        foreach ($files as $file) {
            if ($file === '.' || $file === '..' || $file === 'authorized_keys' || $file === 'known_hosts' || $file === 'config') {
                continue;
            }

            $filePath = $sshDir.'/'.$file;

            if (! is_file($filePath)) {
                continue;
            }

            // Only process key files (id_* pattern or *.pub)
            if (! str_starts_with($file, 'id_') && ! str_ends_with($file, '.pub')) {
                continue;
            }

            $isPublicKeyOnly = str_ends_with($file, '.pub');

            // Skip .pub files if the corresponding private key exists
            if ($isPublicKeyOnly) {
                $privateKeyFile = substr($file, 0, -4);
                if (in_array($privateKeyFile, $files, true)) {
                    continue; // Will be covered by the private key entry
                }
            }

            $type = SshKeyType::fromFilename($file);
            $ageInDays = null;

            $mtime = @filemtime($filePath);
            if ($mtime !== false) {
                $ageInDays = (int) ((time() - $mtime) / 86400);
            }

            // Detect key type from first line if filename didn't help
            if ($type === SshKeyType::Unknown && is_readable($filePath)) {
                $firstLine = $this->readFirstLine($filePath);
                $type = $this->detectTypeFromHeader($firstLine);
            }

            $keys[] = new SshKeyInfo(
                type: $type,
                filename: $file,
                bitLength: null,
                ageInDays: $ageInDays,
                isPublicKeyOnly: $isPublicKeyOnly,
            );
        }

        return $keys;
    }

    private function readFirstLine(string $filePath): string
    {
        $handle = @fopen($filePath, 'r');
        if ($handle === false) {
            return '';
        }

        $line = fgets($handle) ?: '';
        fclose($handle);

        return trim($line);
    }

    private function detectTypeFromHeader(string $header): SshKeyType
    {
        return match (true) {
            str_contains($header, 'RSA') => SshKeyType::Rsa,
            str_contains($header, 'ED25519') || str_contains($header, 'ed25519') => SshKeyType::Ed25519,
            str_contains($header, 'ECDSA') || str_contains($header, 'ecdsa') => SshKeyType::Ecdsa,
            str_contains($header, 'DSA') && ! str_contains($header, 'ECDSA') => SshKeyType::Dsa,
            default => SshKeyType::Unknown,
        };
    }

    private function countAuthorizedKeys(string $sshDir): int
    {
        $authKeysPath = $sshDir.'/authorized_keys';

        if (! is_file($authKeysPath) || ! is_readable($authKeysPath)) {
            return 0;
        }

        $content = @file_get_contents($authKeysPath);
        if ($content === false) {
            return 0;
        }

        $lines = array_filter(
            explode("\n", trim($content)),
            static fn (string $line): bool => $line !== '' && ! str_starts_with(trim($line), '#'),
        );

        return count($lines);
    }

    /**
     * @return array<string>
     */
    private function checkSshConfig(string $configPath): array
    {
        $findings = [];

        if (! is_file($configPath) || ! is_readable($configPath)) {
            return [];
        }

        $content = @file_get_contents($configPath);
        if ($content === false) {
            return [];
        }

        // Check for password authentication
        if (preg_match('/^\s*PasswordAuthentication\s+yes/mi', $content)) {
            $findings[] = 'Password authentication is enabled.';
        }

        // Check for root login
        if (preg_match('/^\s*PermitRootLogin\s+yes/mi', $content)) {
            $findings[] = 'Root login is permitted.';
        }

        return $findings;
    }
}
