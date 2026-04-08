<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityRuntimeEvidence extends Model
{
    protected $table = 'ops_security_runtime_evidence';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'payload_preview' => 'array',
            'recorded_at' => 'immutable_datetime',
        ];
    }
}
