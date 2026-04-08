<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Enable Security Posture Monitoring
    |--------------------------------------------------------------------------
    |
    | When false the manager returns an empty posture summary and no
    | resolvers are invoked. Useful for disabling in local or CI.
    |
    */
    'enabled' => (bool) env('OPS_SECURITY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Cache
    |--------------------------------------------------------------------------
    */
    'cache' => [
        'enabled' => true,
        'ttl' => 300,
        'store' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | SSL / TLS
    |--------------------------------------------------------------------------
    */
    'ssl' => [
        'enabled' => true,
        'domains' => [],
        'timeout' => 10,
        'warning_days' => 30,
        'critical_days' => 7,
    ],

    /*
    |--------------------------------------------------------------------------
    | SSH
    |--------------------------------------------------------------------------
    */
    'ssh' => [
        'enabled' => true,
        'key_directory' => null,
        'config_path' => null,
        'max_key_age_days' => 365,
    ],

    /*
    |--------------------------------------------------------------------------
    | Secrets
    |--------------------------------------------------------------------------
    */
    'secrets' => [
        'enabled' => true,
        'additional' => [],
        'minimum_length' => 16,
        'minimum_entropy' => 3.0,
        'known_defaults' => [
            'password',
            'secret',
            'changeme',
            'your-secret',
            'example',
            'your-api-key',
            'test',
            '',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration Checks
    |--------------------------------------------------------------------------
    */
    'config' => [
        'enabled' => true,
        'production_checks_only' => false,
        'session_max_lifetime' => 480,
        'minimum_bcrypt_rounds' => 12,
    ],

    /*
    |--------------------------------------------------------------------------
    | Timeouts
    |--------------------------------------------------------------------------
    */
    'timeouts' => [
        'overall' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Audit
    |--------------------------------------------------------------------------
    */
    'audit' => [
        'enabled' => true,
        'driver' => env('OPS_SECURITY_AUDIT_DRIVER', 'activitylog'),
        'log_name' => 'ops-security',
    ],

    /*
    |--------------------------------------------------------------------------
    | Visibility Rendering
    |--------------------------------------------------------------------------
    |
    | The ops-security page keeps full counters for recorded visibility data,
    | but only renders a bounded number of the newest records per section to
    | avoid building excessively large Filament schemas in active hosts.
    |
    */
    'visibility' => [
        'display_limit' => 25,
    ],

];
