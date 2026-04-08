<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Enums;

enum SshKeyType: string
{
    case Rsa = 'rsa';
    case Ed25519 = 'ed25519';
    case Ecdsa = 'ecdsa';
    case Dsa = 'dsa';
    case Unknown = 'unknown';

    /**
     * Detect key type from a filename.
     */
    public static function fromFilename(string $filename): self
    {
        $filename = strtolower(basename($filename));

        return match (true) {
            str_contains($filename, 'ed25519') => self::Ed25519,
            str_contains($filename, 'ecdsa') => self::Ecdsa,
            str_contains($filename, 'dsa') && ! str_contains($filename, 'ecdsa') => self::Dsa,
            str_contains($filename, 'rsa') => self::Rsa,
            $filename === 'id_rsa' || $filename === 'id_rsa.pub' => self::Rsa,
            default => self::Unknown,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Rsa => 'RSA',
            self::Ed25519 => 'Ed25519',
            self::Ecdsa => 'ECDSA',
            self::Dsa => 'DSA',
            self::Unknown => 'Unknown',
        };
    }

    /**
     * Whether this key type is considered deprecated.
     */
    public function isDeprecated(): bool
    {
        return $this === self::Dsa;
    }
}
