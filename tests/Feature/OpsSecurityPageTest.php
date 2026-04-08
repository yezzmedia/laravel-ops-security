<?php

declare(strict_types=1);

use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema as SchemaFacade;
use YezzMedia\OpsSecurity\Contracts\SecurityRequestBroker;
use YezzMedia\OpsSecurity\Filament\Pages\OpsSecurityPage;

it('builds the security page schema without invalid schema component calls', function (): void {
    Gate::define('ops-security.posture.view', fn ($user = null) => true);
    Gate::define('ops-security.posture.refresh', fn ($user = null) => true);

    $page = app(OpsSecurityPage::class);
    $schema = $page->content(Schema::make($page));
    $components = $schema->getComponents(withActions: false, withHidden: true);

    expect($components)
        ->toHaveCount(8)
        ->and($components[0])->toBeInstanceOf(Section::class)
        ->and($components[0]->getHeading())->toBe('Overview')
        ->and($components[1])->toBeInstanceOf(Section::class)
        ->and($components[1]->getHeading())->toBe('Governance Overview')
        ->and($components[4])->toBeInstanceOf(Section::class)
        ->and($components[4]->getHeading())->toBe('Visibility Overview')
        ->and($components[5])->toBeInstanceOf(Section::class)
        ->and($components[5]->getHeading())->toBe('Visibility');
});

it('builds the security page schema even when the visibility tables are missing', function (): void {
    Gate::define('ops-security.posture.view', fn ($user = null) => true);
    Gate::define('ops-security.posture.refresh', fn ($user = null) => true);

    SchemaFacade::dropIfExists('ops_security_runtime_evidence');
    SchemaFacade::dropIfExists('ops_security_decisions');
    SchemaFacade::dropIfExists('ops_security_requests');

    $page = app(OpsSecurityPage::class);
    $schema = $page->content(Schema::make($page));

    expect($schema->getComponents(withActions: false, withHidden: true))->toHaveCount(8);
});

it('builds the security page schema with compact visibility history summaries', function (): void {
    Gate::define('ops-security.posture.view', fn ($user = null) => true);
    Gate::define('ops-security.posture.refresh', fn ($user = null) => true);

    $broker = app(SecurityRequestBroker::class);

    foreach (range(1, 40) as $index) {
        $broker->submit('ops-security.request.auth.login-throttle', [
            'guard' => 'web',
            'index' => $index,
        ]);
    }

    $page = app(OpsSecurityPage::class);
    $schema = $page->content(Schema::make($page));
    $components = $schema->getComponents(withActions: false, withHidden: true);

    expect($components)
        ->toHaveCount(8)
        ->and($components[5])->toBeInstanceOf(Section::class)
        ->and($components[5]->getHeading())->toBe('Visibility');
});
