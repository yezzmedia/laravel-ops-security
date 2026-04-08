<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Enums;

enum SecretCategory: string
{
    case Application = 'application';
    case Database = 'database';
    case Mail = 'mail';
    case Cache = 'cache';
    case Queue = 'queue';
    case Api = 'api';
    case Storage = 'storage';
    case Session = 'session';

    public function label(): string
    {
        return match ($this) {
            self::Application => 'Application',
            self::Database => 'Database',
            self::Mail => 'Mail',
            self::Cache => 'Cache',
            self::Queue => 'Queue',
            self::Api => 'API',
            self::Storage => 'Storage',
            self::Session => 'Session',
        };
    }
}
