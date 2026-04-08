<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use Carbon\CarbonImmutable;
use YezzMedia\OpsSecurity\Data\CertificateDetail;

final readonly class CertificateParser
{
    /**
     * Parse openssl_x509_parse() output into a CertificateDetail DTO.
     *
     * @param  array<string, mixed>  $x509Data
     */
    public function parse(array $x509Data, ?string $tlsVersion = null): ?CertificateDetail
    {
        if (! isset($x509Data['subject'], $x509Data['issuer'], $x509Data['validFrom_time_t'], $x509Data['validTo_time_t'])) {
            return null;
        }

        $subject = $x509Data['subject']['CN'] ?? $x509Data['subject']['O'] ?? 'Unknown';
        $issuer = $x509Data['issuer']['CN'] ?? $x509Data['issuer']['O'] ?? 'Unknown';

        $validFrom = CarbonImmutable::createFromTimestamp($x509Data['validFrom_time_t']);
        $validTo = CarbonImmutable::createFromTimestamp($x509Data['validTo_time_t']);
        $daysUntilExpiry = (int) CarbonImmutable::now()->diffInDays($validTo, false);

        $serialNumber = $x509Data['serialNumberHex'] ?? $x509Data['serialNumber'] ?? 'unknown';
        $signatureAlgorithm = $x509Data['signatureTypeSN'] ?? $x509Data['signatureTypeLN'] ?? 'unknown';

        // Extract SANs
        $sans = [];
        $extensions = $x509Data['extensions'] ?? [];
        if (isset($extensions['subjectAltName'])) {
            $rawSans = explode(',', $extensions['subjectAltName']);
            foreach ($rawSans as $san) {
                $san = trim($san);
                if (str_starts_with($san, 'DNS:')) {
                    $sans[] = substr($san, 4);
                }
            }
        }

        $isWildcard = str_starts_with((string) $subject, '*.');
        $isSelfSigned = $this->isSelfSigned($x509Data);
        $chainComplete = ! $isSelfSigned; // Simplified: self-signed certs have incomplete chains

        return new CertificateDetail(
            subject: (string) $subject,
            issuer: (string) $issuer,
            validFrom: $validFrom,
            validTo: $validTo,
            daysUntilExpiry: $daysUntilExpiry,
            serialNumber: (string) $serialNumber,
            signatureAlgorithm: (string) $signatureAlgorithm,
            tlsVersion: $tlsVersion,
            isWildcard: $isWildcard,
            subjectAlternativeNames: $sans,
            isSelfSigned: $isSelfSigned,
            chainComplete: $chainComplete,
        );
    }

    /**
     * @param  array<string, mixed>  $x509Data
     */
    private function isSelfSigned(array $x509Data): bool
    {
        $subject = $x509Data['subject'] ?? [];
        $issuer = $x509Data['issuer'] ?? [];

        return ($subject['CN'] ?? null) === ($issuer['CN'] ?? null)
            && ($subject['O'] ?? null) === ($issuer['O'] ?? null);
    }
}
