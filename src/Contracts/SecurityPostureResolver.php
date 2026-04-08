<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Contracts;

use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;

interface SecurityPostureResolver
{
    /**
     * Which security domain this resolver handles.
     */
    public function domain(): SecurityDomain;

    /**
     * Resolve the full posture result for this domain.
     */
    public function resolve(): DomainPostureResult;
}
