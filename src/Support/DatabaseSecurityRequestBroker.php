<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Support;

use Carbon\CarbonImmutable;
use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Registry\SecurityRequestRegistry;
use YezzMedia\Foundation\Registry\SecurityRequirementRegistry;
use YezzMedia\OpsSecurity\Contracts\SecurityRequestBroker;
use YezzMedia\OpsSecurity\Data\SecurityDecisionRecordData;
use YezzMedia\OpsSecurity\Data\SecurityRequestRecordData;
use YezzMedia\OpsSecurity\Data\SecurityRuntimeEvidenceData;
use YezzMedia\OpsSecurity\Models\SecurityDecisionRecord;
use YezzMedia\OpsSecurity\Models\SecurityRequestRecord;
use YezzMedia\OpsSecurity\Models\SecurityRuntimeEvidence;

class DatabaseSecurityRequestBroker implements SecurityRequestBroker
{
    public function __construct(
        private readonly OpsSecurityVisibilityStoreSetup $storeSetup,
        private readonly SecurityRequestRegistry $securityRequests,
        private readonly SecurityRequirementRegistry $securityRequirements,
        private readonly SecurityPayloadSanitizer $payloadSanitizer,
        private readonly SecurityDecisionResolver $decisionResolver,
    ) {}

    public function submit(string $requestKey, array $payload = [], ?string $source = null, ?string $actor = null): SecurityDecisionRecordData
    {
        $definition = $this->resolveDefinition($requestKey);
        $payloadPreview = $this->payloadSanitizer->preview($definition, $payload);

        if (! $this->storeSetup->storeReady()) {
            return $this->decisionResolver->resolve(
                request: $definition,
                payloadPreview: $payloadPreview,
                requirements: $this->securityRequirements->all()->all(),
                source: $source,
                actor: $actor,
            );
        }

        SecurityRequestRecord::query()->create([
            'request_key' => $definition->key,
            'package' => $definition->package,
            'domain' => $definition->domain,
            'control' => $definition->control,
            'scope' => $definition->scope,
            'requested_level' => $definition->requestedLevel,
            'requested_enforcement_mode' => $definition->requestedEnforcementMode,
            'status' => 'submitted',
            'payload_preview' => $payloadPreview,
            'source' => $source,
            'actor' => $actor,
            'recorded_at' => CarbonImmutable::now(),
        ]);

        $decision = $this->decisionResolver->resolve(
            request: $definition,
            payloadPreview: $payloadPreview,
            requirements: $this->securityRequirements->all()->all(),
            source: $source,
            actor: $actor,
        );

        SecurityDecisionRecord::query()->create([
            'request_key' => $decision->requestKey,
            'package' => $decision->package,
            'domain' => $decision->domain,
            'control' => $decision->control,
            'scope' => $decision->scope,
            'requested_level' => $decision->requestedLevel,
            'requested_enforcement_mode' => $decision->requestedEnforcementMode,
            'effective_level' => $decision->effectiveLevel,
            'effective_enforcement_mode' => $decision->effectiveEnforcementMode,
            'status' => $decision->status,
            'payload_preview' => $decision->payloadPreview,
            'has_conflict' => $decision->hasConflict,
            'conflict_reason' => $decision->conflictReason,
            'source' => $source,
            'actor' => $actor,
            'recorded_at' => $decision->recordedAt,
        ]);

        return $decision;
    }

    public function recordRuntimeUsage(string $requestKey, array $payload = [], ?string $source = null, ?string $actor = null): SecurityRuntimeEvidenceData
    {
        $definition = $this->resolveDefinition($requestKey);
        $payloadPreview = $this->payloadSanitizer->preview($definition, $payload);
        $recordedAt = CarbonImmutable::now();

        if (! $this->storeSetup->storeReady()) {
            return new SecurityRuntimeEvidenceData(
                requestKey: $definition->key,
                package: $definition->package,
                domain: $definition->domain,
                control: $definition->control,
                scope: $definition->scope,
                status: 'observed',
                payloadPreview: $payloadPreview,
                source: $source,
                actor: $actor,
                recordedAt: $recordedAt,
            );
        }

        SecurityRuntimeEvidence::query()->create([
            'request_key' => $definition->key,
            'package' => $definition->package,
            'domain' => $definition->domain,
            'control' => $definition->control,
            'scope' => $definition->scope,
            'status' => 'observed',
            'payload_preview' => $payloadPreview,
            'source' => $source,
            'actor' => $actor,
            'recorded_at' => $recordedAt,
        ]);

        return new SecurityRuntimeEvidenceData(
            requestKey: $definition->key,
            package: $definition->package,
            domain: $definition->domain,
            control: $definition->control,
            scope: $definition->scope,
            status: 'observed',
            payloadPreview: $payloadPreview,
            source: $source,
            actor: $actor,
            recordedAt: $recordedAt,
        );
    }

    public function requests(): array
    {
        if (! $this->storeSetup->storeReady()) {
            return [];
        }

        return SecurityRequestRecord::query()
            ->orderByDesc('recorded_at')
            ->get()
            ->map(static fn (SecurityRequestRecord $record): SecurityRequestRecordData => new SecurityRequestRecordData(
                requestKey: $record->request_key,
                package: $record->package,
                domain: $record->domain,
                control: $record->control,
                scope: $record->scope,
                requestedLevel: $record->requested_level,
                requestedEnforcementMode: $record->requested_enforcement_mode,
                status: $record->status,
                payloadPreview: is_array($record->payload_preview) ? $record->payload_preview : [],
                source: $record->source,
                actor: $record->actor,
                recordedAt: CarbonImmutable::instance($record->recorded_at),
            ))
            ->all();
    }

    public function decisions(): array
    {
        if (! $this->storeSetup->storeReady()) {
            return [];
        }

        return SecurityDecisionRecord::query()
            ->orderByDesc('recorded_at')
            ->get()
            ->map(static fn (SecurityDecisionRecord $record): SecurityDecisionRecordData => new SecurityDecisionRecordData(
                requestKey: $record->request_key,
                package: $record->package,
                domain: $record->domain,
                control: $record->control,
                scope: $record->scope,
                requestedLevel: $record->requested_level,
                requestedEnforcementMode: $record->requested_enforcement_mode,
                effectiveLevel: $record->effective_level,
                effectiveEnforcementMode: $record->effective_enforcement_mode,
                status: $record->status,
                payloadPreview: is_array($record->payload_preview) ? $record->payload_preview : [],
                hasConflict: $record->has_conflict,
                conflictReason: $record->conflict_reason,
                source: $record->source,
                actor: $record->actor,
                recordedAt: CarbonImmutable::instance($record->recorded_at),
            ))
            ->all();
    }

    public function runtimeEvidence(): array
    {
        if (! $this->storeSetup->storeReady()) {
            return [];
        }

        return SecurityRuntimeEvidence::query()
            ->orderByDesc('recorded_at')
            ->get()
            ->map(static fn (SecurityRuntimeEvidence $record): SecurityRuntimeEvidenceData => new SecurityRuntimeEvidenceData(
                requestKey: $record->request_key,
                package: $record->package,
                domain: $record->domain,
                control: $record->control,
                scope: $record->scope,
                status: $record->status,
                payloadPreview: is_array($record->payload_preview) ? $record->payload_preview : [],
                source: $record->source,
                actor: $record->actor,
                recordedAt: CarbonImmutable::instance($record->recorded_at),
            ))
            ->all();
    }

    private function resolveDefinition(string $requestKey): SecurityRequestDefinition
    {
        $definition = $this->securityRequests->all()->firstWhere('key', $requestKey);

        if (! $definition instanceof SecurityRequestDefinition) {
            throw new \InvalidArgumentException(sprintf('Unknown security request [%s].', $requestKey));
        }

        return $definition;
    }
}
