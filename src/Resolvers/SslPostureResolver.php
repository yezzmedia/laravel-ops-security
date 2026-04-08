<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Resolvers;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Data\CertificatePosture;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Enums\CertificateStatus;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\Support\CertificateParser;

final readonly class SslPostureResolver implements SecurityPostureResolver
{
    public function __construct(
        private CertificateParser $parser,
    ) {}

    public function domain(): SecurityDomain
    {
        return SecurityDomain::Ssl;
    }

    public function resolve(): DomainPostureResult
    {
        $startTime = hrtime(true);
        $checkedAt = CarbonImmutable::now();

        $domains = $this->getDomainsToCheck();
        $items = [];
        $statuses = [];

        foreach ($domains as $domain) {
            $posture = $this->checkDomain($domain, $checkedAt);
            $items[] = $posture;
            $statuses[] = $posture->status->toPostureStatus();
        }

        $overallStatus = $statuses === []
            ? SecurityPostureStatus::Unknown
            : SecurityPostureStatus::worstOf($statuses);

        $durationMs = (int) ((hrtime(true) - $startTime) / 1_000_000);

        $healthyCount = count(array_filter($items, static fn (CertificatePosture $p): bool => $p->status === CertificateStatus::Valid));

        return new DomainPostureResult(
            domain: SecurityDomain::Ssl,
            status: $overallStatus,
            summary: sprintf('%d of %d certificates healthy.', $healthyCount, count($items)),
            items: $items,
            checkedAt: $checkedAt,
            durationMs: $durationMs,
        );
    }

    /**
     * @return array<string>
     */
    private function getDomainsToCheck(): array
    {
        $domains = [];

        // Always include APP_URL domain
        $appUrl = config('app.url');
        if (is_string($appUrl) && $appUrl !== '') {
            $parsed = parse_url($appUrl);
            if (isset($parsed['host'])) {
                $domains[] = $parsed['host'];
            }
        }

        // Merge additional domains from config
        $additional = config('ops-security.ssl.domains', []);
        if (is_array($additional)) {
            $domains = array_merge($domains, $additional);
        }

        return array_unique(array_filter($domains));
    }

    private function checkDomain(string $domain, CarbonImmutable $checkedAt): CertificatePosture
    {
        $timeout = (int) config('ops-security.ssl.timeout', 10);
        $warningDays = (int) config('ops-security.ssl.warning_days', 30);
        $criticalDays = (int) config('ops-security.ssl.critical_days', 7);

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $errno = 0;
        $errstr = '';

        $stream = @stream_socket_client(
            "ssl://{$domain}:443",
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($stream === false) {
            return new CertificatePosture(
                domain: $domain,
                status: CertificateStatus::Unreachable,
                certificate: null,
                error: "Connection failed: {$errstr} (errno: {$errno})",
                checkedAt: $checkedAt,
            );
        }

        $params = stream_context_get_params($stream);
        fclose($stream);

        $peerCert = $params['options']['ssl']['peer_certificate'] ?? null;

        if ($peerCert === null) {
            return new CertificatePosture(
                domain: $domain,
                status: CertificateStatus::Invalid,
                certificate: null,
                error: 'No peer certificate available.',
                checkedAt: $checkedAt,
            );
        }

        $x509Data = openssl_x509_parse($peerCert);

        if ($x509Data === false) {
            return new CertificatePosture(
                domain: $domain,
                status: CertificateStatus::Invalid,
                certificate: null,
                error: 'Failed to parse certificate.',
                checkedAt: $checkedAt,
            );
        }

        // Detect TLS version from stream metadata
        $meta = stream_get_meta_data($stream ?? fopen('php://memory', 'r'));
        $tlsVersion = $meta['crypto']['protocol'] ?? null;

        $detail = $this->parser->parse($x509Data, $tlsVersion);

        if ($detail === null) {
            return new CertificatePosture(
                domain: $domain,
                status: CertificateStatus::Invalid,
                certificate: null,
                error: 'Certificate data is malformed or incomplete.',
                checkedAt: $checkedAt,
            );
        }

        // Determine certificate status based on expiry
        $status = match (true) {
            $detail->daysUntilExpiry < 0 => CertificateStatus::Expired,
            $detail->daysUntilExpiry <= $criticalDays => CertificateStatus::Expired,
            $detail->daysUntilExpiry <= $warningDays => CertificateStatus::ExpiringSoon,
            default => CertificateStatus::Valid,
        };

        return new CertificatePosture(
            domain: $domain,
            status: $status,
            certificate: $detail,
            error: null,
            checkedAt: $checkedAt,
        );
    }
}
