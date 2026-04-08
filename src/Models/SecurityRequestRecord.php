<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityRequestRecord extends Model
{
    protected $table = 'ops_security_requests';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'payload_preview' => 'array',
            'recorded_at' => 'immutable_datetime',
        ];
    }
}
