<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity\Filament\Pages;

use BackedEnum;
use Filament\Actions\Action;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Schemas\Components\Actions;
use Filament\Schemas\Components\Grid;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Tabs;
use Filament\Schemas\Components\Tabs\Tab;
use Filament\Schemas\Components\Text;
use Filament\Schemas\Schema;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use UnitEnum;
use YezzMedia\Foundation\Data\SecurityRequestDefinition;
use YezzMedia\Foundation\Data\SecurityRequirementDefinition;
use YezzMedia\OpsSecurity\Actions\RefreshSecurityPostureAction;
use YezzMedia\OpsSecurity\Data\CertificatePosture;
use YezzMedia\OpsSecurity\Data\DomainPostureResult;
use YezzMedia\OpsSecurity\Data\EffectiveSecurityControl;
use YezzMedia\OpsSecurity\Data\SecretCheckItem;
use YezzMedia\OpsSecurity\Data\SecurityAlert;
use YezzMedia\OpsSecurity\Data\SecurityConfigItem;
use YezzMedia\OpsSecurity\Data\SecurityDecisionRecordData;
use YezzMedia\OpsSecurity\Data\SecurityGovernanceSummary;
use YezzMedia\OpsSecurity\Data\SecurityPostureSummary;
use YezzMedia\OpsSecurity\Data\SecurityRequestRecordData;
use YezzMedia\OpsSecurity\Data\SecurityRuntimeEvidenceData;
use YezzMedia\OpsSecurity\Data\SecurityVisibilitySummary;
use YezzMedia\OpsSecurity\Data\SshKeyInfo;
use YezzMedia\OpsSecurity\Enums\SecurityDomain;
use YezzMedia\OpsSecurity\Enums\SecurityPostureStatus;
use YezzMedia\OpsSecurity\OpsSecurityManager;

class OpsSecurityPage extends Page
{
    protected static BackedEnum|string|null $navigationIcon = 'heroicon-o-shield-check';

    protected static string|UnitEnum|null $navigationGroup = 'Security';

    protected static ?string $navigationLabel = 'Security Posture';

    protected static ?int $navigationSort = 70;

    protected static ?string $title = 'Security Posture';

    protected static ?string $slug = 'ops-security';

    public static function canAccess(): bool
    {
        return Gate::check('ops-security.posture.view');
    }

    public static function getNavigationBadge(): ?string
    {
        return app(OpsSecurityManager::class)->status()->label();
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return app(OpsSecurityManager::class)->status()->color();
    }

    public function content(Schema $schema): Schema
    {
        $manager = app(OpsSecurityManager::class);
        $summary = $manager->posture();
        $governance = $manager->governance();
        $visibility = $manager->visibility();

        return $schema->components([
            $this->overviewSection($summary),
            $this->governanceOverviewSection($governance),
            $this->domainTabs($summary),
            $this->governanceDetailsSection($governance),
            $this->visibilityOverviewSection($visibility),
            $this->visibilityDetailsSection($visibility),
            $this->alertsSection($summary),
            $this->actionsSection(),
        ]);
    }

    private function governanceOverviewSection(SecurityGovernanceSummary $governance): Section
    {
        return Section::make('Governance Overview')
            ->schema([
                Grid::make(4)->schema([
                    ...$this->labeledText(
                        'Declared Requests',
                        (string) $governance->requestCount,
                        color: $governance->requestCount > 0 ? 'primary' : 'gray',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Declared Requirements',
                        (string) $governance->requirementCount,
                        color: $governance->requirementCount > 0 ? 'primary' : 'gray',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Declaring Packages',
                        (string) $governance->packageCount,
                        color: $governance->packageCount > 0 ? 'primary' : 'gray',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Conflicts',
                        (string) $governance->conflictCount,
                        color: $governance->conflictCount > 0 ? 'danger' : 'success',
                        icon: $governance->conflictCount > 0 ? 'heroicon-o-exclamation-circle' : 'heroicon-o-check-circle',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Verified Controls',
                        (string) $governance->verifiedCount,
                        color: $governance->verifiedCount > 0 ? 'success' : 'gray',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Observed Controls',
                        (string) $governance->observedCount,
                        color: $governance->observedCount > 0 ? 'gray' : 'success',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Drifted Controls',
                        (string) $governance->driftCount,
                        color: $governance->driftCount > 0 ? 'danger' : 'success',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Missing Capabilities',
                        (string) $governance->unmetCapabilityCount,
                        color: $governance->unmetCapabilityCount > 0 ? 'warning' : 'success',
                        badge: true,
                    ),
                ]),
            ]);
    }

    private function overviewSection(SecurityPostureSummary $summary): Section
    {
        $alertCount = count($summary->alerts);
        $criticalCount = count(array_filter(
            $summary->alerts,
            static fn (SecurityAlert $a): bool => $a->severity === SecurityPostureStatus::Critical,
        ));
        $warningCount = count(array_filter(
            $summary->alerts,
            static fn (SecurityAlert $a): bool => $a->severity === SecurityPostureStatus::Warning,
        ));

        return Section::make('Overview')
            ->schema([
                Grid::make(4)->schema([
                    ...$this->labeledText(
                        'Overall Status',
                        $summary->status->label(),
                        color: $summary->status->color(),
                        icon: $summary->status->icon(),
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Alerts',
                        (string) $alertCount,
                        color: $alertCount > 0 ? 'danger' : 'gray',
                        icon: 'heroicon-o-bell-alert',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Critical',
                        (string) $criticalCount,
                        color: $criticalCount > 0 ? 'danger' : 'gray',
                        icon: 'heroicon-o-x-circle',
                        badge: true,
                    ),
                    ...$this->labeledText(
                        'Warnings',
                        (string) $warningCount,
                        color: $warningCount > 0 ? 'warning' : 'gray',
                        icon: 'heroicon-o-exclamation-triangle',
                        badge: true,
                    ),
                ]),
                Grid::make(2)->schema([
                    ...$this->labeledText(
                        'Last resolved',
                        $summary->resolvedAt->format('Y-m-d H:i:s T'),
                        color: 'gray',
                    ),
                    ...$this->labeledText(
                        'Duration',
                        $summary->resolverDurationMs.' ms',
                        color: 'gray',
                    ),
                ]),
            ]);
    }

    private function domainTabs(SecurityPostureSummary $summary): Tabs
    {
        $tabs = [];

        foreach (SecurityDomain::cases() as $domain) {
            if (isset($summary->domains[$domain->value])) {
                $tabs[] = $this->domainTab($summary->domains[$domain->value]);
            }
        }

        return Tabs::make('domains')->tabs($tabs);
    }

    private function domainTab(DomainPostureResult $result): Tab
    {
        return Tab::make($result->domain->label())
            ->icon($result->status->icon())
            ->badgeColor($result->status->color())
            ->schema([
                Grid::make(3)->schema([
                    ...$this->labeledText(
                        'Status',
                        $result->status->label(),
                        color: $result->status->color(),
                        icon: $result->status->icon(),
                        badge: true,
                    ),
                    ...$this->labeledText('Summary', $result->summary),
                    ...$this->labeledText(
                        'Duration',
                        $result->durationMs.' ms',
                        color: 'gray',
                    ),
                ]),
                ...$this->domainItems($result),
            ]);
    }

    /**
     * @return array<int, Section>
     */
    private function domainItems(DomainPostureResult $result): array
    {
        if ($result->items === []) {
            return [];
        }

        $itemComponents = [];

        foreach ($result->items as $item) {
            $component = match (true) {
                $item instanceof CertificatePosture => $this->certificateItem($item),
                $item instanceof SshKeyInfo => $this->sshKeyItem($item),
                $item instanceof SecretCheckItem => $this->secretItem($item),
                $item instanceof SecurityConfigItem => $this->configItem($item),
                default => null,
            };

            if ($component !== null) {
                $itemComponents[] = $component;
            }
        }

        if ($itemComponents === []) {
            return [];
        }

        return [
            Section::make('Details')
                ->schema($itemComponents),
        ];
    }

    private function certificateItem(CertificatePosture $cert): Grid
    {
        $status = $cert->status->toPostureStatus();

        $schema = [
            ...$this->labeledText('Domain', $cert->domain),
            ...$this->labeledText(
                'Status',
                $cert->status->label(),
                color: $status->color(),
                icon: $status->icon(),
                badge: true,
            ),
        ];

        if ($cert->certificate !== null) {
            $schema = [
                ...$schema,
                ...$this->labeledText('Issuer', $cert->certificate->issuer),
                ...$this->labeledText(
                    'Expires',
                    $cert->certificate->validTo->format('Y-m-d').' ('.$cert->certificate->daysUntilExpiry.' days)',
                    color: $cert->certificate->daysUntilExpiry < 30 ? 'warning' : 'success',
                ),
            ];
        }

        if ($cert->error !== null) {
            $schema = [
                ...$schema,
                ...$this->labeledText('Error', $cert->error, color: 'danger'),
            ];
        }

        return Grid::make(2)->schema($schema);
    }

    private function sshKeyItem(SshKeyInfo $key): Grid
    {
        $typeColor = $key->type->isDeprecated() ? 'warning' : 'success';

        return Grid::make(4)->schema([
            ...$this->labeledText('Key', $key->filename),
            ...$this->labeledText(
                'Type',
                $key->type->label(),
                color: $typeColor,
                badge: true,
            ),
            ...$this->labeledText(
                'Bits',
                $key->bitLength !== null ? (string) $key->bitLength : 'N/A',
            ),
            ...$this->labeledText(
                'Age',
                $key->ageInDays !== null ? $key->ageInDays.' days' : 'Unknown',
                color: ($key->ageInDays !== null && $key->ageInDays > 365) ? 'warning' : 'gray',
            ),
        ]);
    }

    private function secretItem(SecretCheckItem $item): Grid
    {
        return Grid::make(4)->schema([
            ...$this->labeledText('Secret', $item->name),
            ...$this->labeledText(
                'Status',
                $item->status->label(),
                color: $item->status->color(),
                icon: $item->status->icon(),
                badge: true,
            ),
            ...$this->labeledText(
                'Category',
                $item->category->label(),
                badge: true,
                color: 'gray',
            ),
            ...$this->labeledText(
                'Finding',
                $item->finding ?? 'OK',
                color: $item->finding !== null ? $item->status->color() : 'success',
            ),
        ]);
    }

    private function configItem(SecurityConfigItem $item): Grid
    {
        return Grid::make(4)->schema([
            ...$this->labeledText('Check', $item->label),
            ...$this->labeledText(
                'Status',
                $item->status->label(),
                color: $item->status->color(),
                icon: $item->status->icon(),
                badge: true,
            ),
            ...$this->labeledText('Current', $item->currentState),
            ...$this->labeledText(
                'Expected',
                $item->expectedState,
                color: $item->currentState === $item->expectedState ? 'success' : 'warning',
            ),
        ]);
    }

    private function alertsSection(SecurityPostureSummary $summary): Section
    {
        if ($summary->alerts === []) {
            return Section::make('Alerts')
                ->schema([
                    Text::make('No active alerts.')
                        ->color('success')
                        ->icon('heroicon-o-check-circle'),
                ]);
        }

        $alertComponents = [];

        foreach ($summary->alerts as $alert) {
            $alertComponents[] = Grid::make(4)->schema([
                ...$this->labeledText(
                    'Severity',
                    $alert->severity->label(),
                    color: $alert->severity->color(),
                    icon: $alert->severity->icon(),
                    badge: true,
                ),
                ...$this->labeledText(
                    'Domain',
                    $alert->domain->label(),
                    badge: true,
                    color: 'gray',
                ),
                ...$this->labeledText('Title', $alert->title),
                ...$this->labeledText('Recommendation', $alert->recommendation),
            ]);
        }

        return Section::make('Alerts ('.count($summary->alerts).')')
            ->schema($alertComponents);
    }

    private function governanceDetailsSection(SecurityGovernanceSummary $governance): Section
    {
        return Section::make('Governance')
            ->schema([
                Tabs::make('governance-tabs')->tabs([
                    Tab::make('Declared Requests')
                        ->schema($this->declaredRequestComponents($governance)),
                    Tab::make('Declared Requirements')
                        ->schema($this->declaredRequirementComponents($governance)),
                    Tab::make('Effective Policy')
                        ->schema($this->effectivePolicyComponents($governance)),
                    Tab::make('Verification & Drift')
                        ->schema($this->verificationComponents($governance)),
                    Tab::make('Remediation')
                        ->schema($this->remediationComponents($governance)),
                ]),
            ]);
    }

    /**
     * @return array<int, Section|Text>
     */
    private function declaredRequestComponents(SecurityGovernanceSummary $governance): array
    {
        if ($governance->requestsByPackage === []) {
            return [
                Text::make('No security requests declared.')
                    ->color('gray'),
            ];
        }

        $components = [];

        foreach ($governance->requestsByPackage as $package => $requests) {
            $requestComponents = [];

            foreach ($requests as $request) {
                $requestComponents[] = $this->declaredRequestGrid($request);
            }

            $components[] = Section::make($package)
                ->schema($requestComponents);
        }

        return $components;
    }

    private function declaredRequestGrid(SecurityRequestDefinition $request): Text
    {
        return Text::make($this->declaredRequestSummary($request))
            ->columnSpanFull()
            ->color('gray');
    }

    /**
     * @return array<int, Section|Text>
     */
    private function declaredRequirementComponents(SecurityGovernanceSummary $governance): array
    {
        if ($governance->requirementsByPackage === []) {
            return [
                Text::make('No security requirements declared.')
                    ->color('gray'),
            ];
        }

        $components = [];

        foreach ($governance->requirementsByPackage as $package => $requirements) {
            $requirementComponents = [];

            foreach ($requirements as $requirement) {
                $requirementComponents[] = $this->declaredRequirementGrid($requirement);
            }

            $components[] = Section::make($package)
                ->schema($requirementComponents);
        }

        return $components;
    }

    private function declaredRequirementGrid(SecurityRequirementDefinition $requirement): Text
    {
        return Text::make($this->declaredRequirementSummary($requirement))
            ->columnSpanFull()
            ->color('gray');
    }

    /**
     * @return array<int, Text>
     */
    private function effectivePolicyComponents(SecurityGovernanceSummary $governance): array
    {
        if ($governance->effectiveControls === []) {
            return [
                Text::make('No effective policy is available.')
                    ->color('gray'),
            ];
        }

        return array_map(
            fn (EffectiveSecurityControl $control): Text => $this->effectivePolicyGrid($control),
            $governance->effectiveControls,
        );
    }

    private function effectivePolicyGrid(EffectiveSecurityControl $control): Text
    {
        return Text::make($this->effectivePolicySummary($control))
            ->columnSpanFull()
            ->color('gray');
    }

    /**
     * @return array<int, Text>
     */
    private function verificationComponents(SecurityGovernanceSummary $governance): array
    {
        if ($governance->effectiveControls === []) {
            return [
                Text::make('No runtime verification data is available.')
                    ->color('gray'),
            ];
        }

        return array_map(
            fn (EffectiveSecurityControl $control): Text => Text::make($this->verificationSummary($control))
                ->columnSpanFull()
                ->color('gray'),
            $governance->effectiveControls,
        );
    }

    private function declaredRequestSummary(SecurityRequestDefinition $request): string
    {
        return implode(' | ', [
            'Domain: '.Str::headline($request->domain),
            'Control: '.Str::headline($request->control),
            'Scope: '.$request->scope,
            'Requested Level: '.Str::headline($request->requestedLevel),
            'Requested Enforcement: '.Str::headline($request->requestedEnforcementMode),
            'Preview Fields: '.($request->allowedPreviewFields !== [] ? implode(', ', $request->allowedPreviewFields) : 'None'),
            'Masked Fields: '.($request->maskedFields !== [] ? implode(', ', $request->maskedFields) : 'None'),
            'Description: '.$request->description,
        ]);
    }

    private function declaredRequirementSummary(SecurityRequirementDefinition $requirement): string
    {
        return implode(' | ', [
            'Domain: '.Str::headline($requirement->domain),
            'Control: '.Str::headline($requirement->control),
            'Level: '.Str::headline($requirement->level),
            'Scope: '.$requirement->scope,
            'Enforcement: '.Str::headline($requirement->enforcementMode),
            'Applies To: '.($requirement->appliesTo !== [] ? implode(', ', $requirement->appliesTo) : 'All'),
            'Description: '.$requirement->description,
            'Notes: '.($requirement->notes ?? 'None'),
        ]);
    }

    private function effectivePolicySummary(EffectiveSecurityControl $control): string
    {
        return implode(' | ', [
            'Domain: '.Str::headline($control->domain),
            'Control: '.Str::headline($control->control),
            'Scope: '.$control->scope,
            'Effective Level: '.Str::headline($control->level),
            'Enforcement: '.Str::headline($control->enforcementMode),
            'Packages: '.($control->packages !== [] ? implode(', ', $control->packages) : 'None'),
            'Requirements: '.($control->requirementKeys !== [] ? implode(', ', $control->requirementKeys) : 'None'),
            'Requests: '.($control->requestKeys !== [] ? implode(', ', $control->requestKeys) : 'None'),
            'Request Packages: '.($control->requestPackages !== [] ? implode(', ', $control->requestPackages) : 'None'),
            'Verification: '.Str::headline($control->verificationStatus),
            'Summary: '.$control->verificationSummary,
            'Conflict: '.($control->hasConflict ? ($control->conflictReason ?? 'Conflict detected') : 'None'),
        ]);
    }

    private function verificationSummary(EffectiveSecurityControl $control): string
    {
        return implode(' | ', [
            'Domain: '.Str::headline($control->domain),
            'Control: '.Str::headline($control->control),
            'Scope: '.$control->scope,
            'Verification Status: '.Str::headline($control->verificationStatus),
            'Summary: '.$control->verificationSummary,
            'Drift: '.($control->driftReason ?? 'No active drift detected'),
            'Missing Capabilities: '.($control->missingCapabilities !== [] ? implode(', ', $control->missingCapabilities) : 'None'),
            'Recommended Actions: '.($control->recommendedActions !== [] ? implode(' | ', $control->recommendedActions) : 'None'),
        ]);
    }

    /**
     * @return array<int, Section|Text>
     */
    private function remediationComponents(SecurityGovernanceSummary $governance): array
    {
        if ($governance->remediationRecommendations === []) {
            return [
                Text::make('No remediation actions are currently required.')
                    ->color('success')
                    ->icon('heroicon-o-check-circle'),
            ];
        }

        return [
            Section::make('Recommended Actions')
                ->schema(array_map(
                    fn (string $recommendation): Text => Text::make($recommendation)
                        ->badge()
                        ->color('warning'),
                    $governance->remediationRecommendations,
                )),
        ];
    }

    private function visibilityOverviewSection(SecurityVisibilitySummary $visibility): Section
    {
        return Section::make('Visibility Overview')
            ->schema([
                Grid::make(4)->schema([
                    ...$this->labeledText('Requests', (string) $visibility->requestCount, color: 'primary', badge: true),
                    ...$this->labeledText('Decisions', (string) $visibility->decisionCount, color: 'primary', badge: true),
                    ...$this->labeledText('Runtime Evidence', (string) $visibility->runtimeEvidenceCount, color: 'primary', badge: true),
                    ...$this->labeledText(
                        'Conflict Decisions',
                        (string) $visibility->conflictDecisionCount,
                        color: $visibility->conflictDecisionCount > 0 ? 'danger' : 'success',
                        badge: true,
                    ),
                ]),
                Grid::make(3)->schema([
                    ...$this->labeledText('Displaying Requests', sprintf('%d of %d', $visibility->requestDisplayCount, $visibility->requestCount), color: 'gray'),
                    ...$this->labeledText('Displaying Decisions', sprintf('%d of %d', $visibility->decisionDisplayCount, $visibility->decisionCount), color: 'gray'),
                    ...$this->labeledText('Displaying Evidence', sprintf('%d of %d', $visibility->runtimeEvidenceDisplayCount, $visibility->runtimeEvidenceCount), color: 'gray'),
                ]),
            ]);
    }

    private function visibilityDetailsSection(SecurityVisibilitySummary $visibility): Section
    {
        return Section::make('Visibility')
            ->schema([
                Tabs::make('visibility-tabs')->tabs([
                    Tab::make('Incoming Requests')
                        ->schema($this->requestRecordComponents($visibility)),
                    Tab::make('Decisions')
                        ->schema($this->decisionRecordComponents($visibility)),
                    Tab::make('Runtime Evidence')
                        ->schema($this->runtimeEvidenceComponents($visibility)),
                ]),
            ]);
    }

    /**
     * @return array<int, Grid|Text>
     */
    private function requestRecordComponents(SecurityVisibilitySummary $visibility): array
    {
        if ($visibility->requests === []) {
            return [Text::make('No incoming requests recorded.')->color('gray')];
        }

        return array_map(
            fn (SecurityRequestRecordData $request): Text => Text::make($this->requestRecordSummary($request))
                ->columnSpanFull()
                ->color('gray'),
            $visibility->requests,
        );
    }

    /**
     * @return array<int, Grid|Text>
     */
    private function decisionRecordComponents(SecurityVisibilitySummary $visibility): array
    {
        if ($visibility->decisions === []) {
            return [Text::make('No decisions recorded.')->color('gray')];
        }

        return array_map(
            fn (SecurityDecisionRecordData $decision): Text => Text::make($this->decisionRecordSummary($decision))
                ->columnSpanFull()
                ->color('gray'),
            $visibility->decisions,
        );
    }

    /**
     * @return array<int, Grid|Text>
     */
    private function runtimeEvidenceComponents(SecurityVisibilitySummary $visibility): array
    {
        if ($visibility->runtimeEvidence === []) {
            return [Text::make('No runtime evidence recorded.')->color('gray')];
        }

        return array_map(
            fn (SecurityRuntimeEvidenceData $evidence): Text => Text::make($this->runtimeEvidenceSummary($evidence))
                ->columnSpanFull()
                ->color('gray'),
            $visibility->runtimeEvidence,
        );
    }

    private function requestRecordSummary(SecurityRequestRecordData $request): string
    {
        return implode(' | ', [
            'Package: '.$request->package,
            'Control: '.Str::headline($request->control),
            'Scope: '.$request->scope,
            'Status: '.Str::headline($request->status),
            'Source: '.($request->source ?? 'Unknown'),
            'Actor: '.($request->actor ?? 'System'),
            'Recorded: '.$request->recordedAt->format('Y-m-d H:i:s T'),
            'Payload: '.$this->previewText($request->payloadPreview),
        ]);
    }

    private function decisionRecordSummary(SecurityDecisionRecordData $decision): string
    {
        return implode(' | ', [
            'Package: '.$decision->package,
            'Control: '.Str::headline($decision->control),
            'Effective Level: '.Str::headline($decision->effectiveLevel),
            'Enforcement: '.Str::headline($decision->effectiveEnforcementMode),
            'Status: '.Str::headline($decision->status),
            'Conflict: '.($decision->conflictReason ?? 'None'),
            'Source: '.($decision->source ?? 'Unknown'),
            'Payload: '.$this->previewText($decision->payloadPreview),
        ]);
    }

    private function runtimeEvidenceSummary(SecurityRuntimeEvidenceData $evidence): string
    {
        return implode(' | ', [
            'Package: '.$evidence->package,
            'Control: '.Str::headline($evidence->control),
            'Scope: '.$evidence->scope,
            'Status: '.Str::headline($evidence->status),
            'Source: '.($evidence->source ?? 'Unknown'),
            'Actor: '.($evidence->actor ?? 'System'),
            'Recorded: '.$evidence->recordedAt->format('Y-m-d H:i:s T'),
            'Payload: '.$this->previewText($evidence->payloadPreview),
        ]);
    }

    /**
     * @param  array<string, scalar|null>  $preview
     */
    private function previewText(array $preview): string
    {
        if ($preview === []) {
            return 'No preview data';
        }

        return collect($preview)
            ->map(fn ($value, $key) => $key.'='.(is_bool($value) ? ($value ? 'true' : 'false') : ($value ?? 'null')))
            ->implode(', ');
    }

    private function actionsSection(): Actions
    {
        return Actions::make([
            Action::make('refresh')
                ->label('Refresh Security Posture')
                ->icon('heroicon-o-arrow-path')
                ->color('primary')
                ->requiresConfirmation()
                ->modalHeading('Refresh Security Posture')
                ->modalDescription('This will probe all security domains and generate a fresh posture snapshot. This may take a moment.')
                ->visible(fn (): bool => Gate::check('ops-security.posture.refresh'))
                ->action(function (): void {
                    app(RefreshSecurityPostureAction::class)->execute('filament');

                    Notification::make()
                        ->success()
                        ->title('Security posture refreshed')
                        ->send();
                }),
        ]);
    }

    /**
     * @return array{Text, Text}
     */
    private function labeledText(
        string $label,
        string $value,
        ?string $color = null,
        ?string $icon = null,
        bool $badge = false,
    ): array {
        $valueText = Text::make($value);

        if ($badge) {
            $valueText = $valueText->badge();
        }

        if ($color !== null) {
            $valueText = $valueText->color($color);
        }

        if ($icon !== null) {
            $valueText = $valueText->icon($icon);
        }

        return [
            Text::make($label)
                ->badge()
                ->color('gray'),
            $valueText,
        ];
    }

    private function governanceLevelColor(string $level): string
    {
        return match ($level) {
            'required' => 'danger',
            'recommended' => 'warning',
            'disallowed' => 'gray',
            default => 'success',
        };
    }

    private function enforcementModeColor(string $enforcementMode): string
    {
        return match ($enforcementMode) {
            'centrally_enforced' => 'danger',
            'package_owned' => 'primary',
            default => 'gray',
        };
    }

    private function verificationStatusColor(string $status): string
    {
        return match ($status) {
            'verified' => 'success',
            'drift' => 'danger',
            'unmet' => 'warning',
            default => 'gray',
        };
    }
}
