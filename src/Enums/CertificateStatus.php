<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Enums;

enum CertificateStatus: string
{
    case Valid = 'valid';
    case ExpiringSoon = 'expiring_soon';
    case Expired = 'expired';
    case Invalid = 'invalid';
    case Unreachable = 'unreachable';

    public function toPostureStatus(): SecurityPostureStatus
    {
        return match ($this) {
            self::Valid => SecurityPostureStatus::Healthy,
            self::ExpiringSoon => SecurityPostureStatus::Warning,
            self::Expired => SecurityPostureStatus::Critical,
            self::Invalid => SecurityPostureStatus::Critical,
            self::Unreachable => SecurityPostureStatus::Unknown,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Valid => 'Valid',
            self::ExpiringSoon => 'Expiring Soon',
            self::Expired => 'Expired',
            self::Invalid => 'Invalid',
            self::Unreachable => 'Unreachable',
        };
    }
}
