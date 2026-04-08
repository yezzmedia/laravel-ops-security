<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Enums;

enum SecurityDomain: string
{
    case Ssl = 'ssl';
    case Ssh = 'ssh';
    case Secret = 'secret';
    case Config = 'config';

    public function label(): string
    {
        return match ($this) {
            self::Ssl => 'SSL/TLS Certificates',
            self::Ssh => 'SSH Access',
            self::Secret => 'Application Secrets',
            self::Config => 'Security Configuration',
        };
    }

    /**
     * Return the config path for the domain's enabled flag.
     */
    public function configKey(): string
    {
        return match ($this) {
            self::Ssl => 'ops-security.ssl.enabled',
            self::Ssh => 'ops-security.ssh.enabled',
            self::Secret => 'ops-security.secrets.enabled',
            self::Config => 'ops-security.config.enabled',
        };
    }
}
