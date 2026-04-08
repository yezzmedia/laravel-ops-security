<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityDecisionRecord extends Model
{
    protected $table = 'ops_security_decisions';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'payload_preview' => 'array',
            'has_conflict' => 'bool',
            'recorded_at' => 'immutable_datetime',
        ];
    }
}
