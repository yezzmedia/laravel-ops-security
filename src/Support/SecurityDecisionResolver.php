<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;
use YezzMedia\OpsSecurity\Data\SecurityDecisionRecordData;

class SecurityDecisionResolver
{
    /**
     * @param  array<string, scalar|null>  $payloadPreview
     * @param  array<int, SecurityRequirementDefinition>  $requirements
     */
    public function resolve(
        SecurityRequestDefinition $request,
        array $payloadPreview,
        array $requirements,
        ?string $source,
        ?string $actor,
    ): SecurityDecisionRecordData {
        $matchingRequirements = array_values(array_filter(
            $requirements,
            static fn (SecurityRequirementDefinition $requirement): bool => $requirement->domain === $request->domain
                && $requirement->control === $request->control
                && $requirement->scope === $request->scope,
        ));

        $effectiveLevel = $this->resolveEffectiveLevel($request->requestedLevel, $matchingRequirements);
        $effectiveEnforcementMode = $this->resolveEffectiveEnforcementMode($request->requestedEnforcementMode, $matchingRequirements);

        $hasConflict = in_array('disallowed', array_map(
            static fn (SecurityRequirementDefinition $requirement): string => $requirement->level,
            $matchingRequirements,
        ), true) && $request->requestedLevel !== 'disallowed';

        return new SecurityDecisionRecordData(
            requestKey: $request->key,
            package: $request->package,
            domain: $request->domain,
            control: $request->control,
            scope: $request->scope,
            requestedLevel: $request->requestedLevel,
            requestedEnforcementMode: $request->requestedEnforcementMode,
            effectiveLevel: $effectiveLevel,
            effectiveEnforcementMode: $effectiveEnforcementMode,
            status: $hasConflict ? 'conflict' : 'applied',
            payloadPreview: $payloadPreview,
            hasConflict: $hasConflict,
            conflictReason: $hasConflict ? 'A stricter disallowed requirement conflicts with the submitted request.' : null,
            source: $source,
            actor: $actor,
            recordedAt: now()->toImmutable(),
        );
    }

    /**
     * @param  array<int, SecurityRequirementDefinition>  $requirements
     */
    private function resolveEffectiveLevel(string $requestedLevel, array $requirements): string
    {
        $levels = array_merge([$requestedLevel], array_map(
            static fn (SecurityRequirementDefinition $requirement): string => $requirement->level,
            $requirements,
        ));

        foreach (['disallowed', 'required', 'recommended', 'optional'] as $level) {
            if (in_array($level, $levels, true)) {
                return $level;
            }
        }

        return 'optional';
    }

    /**
     * @param  array<int, SecurityRequirementDefinition>  $requirements
     */
    private function resolveEffectiveEnforcementMode(string $requestedMode, array $requirements): string
    {
        $modes = array_merge([$requestedMode], array_map(
            static fn (SecurityRequirementDefinition $requirement): string => $requirement->enforcementMode,
            $requirements,
        ));

        foreach (['centrally_enforced', 'package_owned', 'observe_only'] as $mode) {
            if (in_array($mode, $modes, true)) {
                return $mode;
            }
        }

        return 'observe_only';
    }
}
