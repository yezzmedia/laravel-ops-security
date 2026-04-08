<?php

declare(strict_types=1);

namespace YezzMedia\OpsSecurity;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Spatie\Activitylog\Support\ActivityLogger;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use YezzMedia\Foundation\Registry\SecurityRequestRegistry;
use YezzMedia\Foundation\Registry\SecurityRequirementRegistry;
use YezzMedia\Foundation\Support\PlatformPackageRegistrar;
use YezzMedia\OpsSecurity\Actions\RefreshSecurityPostureAction;
use YezzMedia\OpsSecurity\Audit\ActivityLogSecurityAuditWriter;
use YezzMedia\OpsSecurity\Audit\NullSecurityAuditWriter;
use YezzMedia\OpsSecurity\Contracts\SecurityAuditWriter;
use YezzMedia\OpsSecurity\Contracts\SecurityPostureResolver;
use YezzMedia\OpsSecurity\Contracts\SecurityRequestBroker;
use YezzMedia\OpsSecurity\Doctor\LoginThrottleCheck;
use YezzMedia\OpsSecurity\Doctor\PasswordConfirmationCheck;
use YezzMedia\OpsSecurity\Doctor\PrivilegedMfaCheck;
use YezzMedia\OpsSecurity\Doctor\SecretHealthCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityConfigCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityDriftCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityPolicyConflictCheck;
use YezzMedia\OpsSecurity\Doctor\SecurityResolverCheck;
use YezzMedia\OpsSecurity\Doctor\SshPostureCheck;
use YezzMedia\OpsSecurity\Doctor\SslPostureCheck;
use YezzMedia\OpsSecurity\Events\SecurityPostureRefreshed;
use YezzMedia\OpsSecurity\Install\EnsureOpsSecurityVisibilityStoreReadyInstallStep;
use YezzMedia\OpsSecurity\Install\PublishSecurityConfigStep;
use YezzMedia\OpsSecurity\Install\VerifyOpenSslExtensionStep;
use YezzMedia\OpsSecurity\Install\VerifyOpsDependencyStep;
use YezzMedia\OpsSecurity\Listeners\WriteSecurityAuditEntry;
use YezzMedia\OpsSecurity\Resolvers\SecretHealthResolver;
use YezzMedia\OpsSecurity\Resolvers\SecurityConfigResolver;
use YezzMedia\OpsSecurity\Resolvers\SshPostureResolver;
use YezzMedia\OpsSecurity\Resolvers\SslPostureResolver;
use YezzMedia\OpsSecurity\Support\CertificateParser;
use YezzMedia\OpsSecurity\Support\DatabaseSecurityRequestBroker;
use YezzMedia\OpsSecurity\Support\EntropyAnalyzer;
use YezzMedia\OpsSecurity\Support\OpsSecurityVisibilityStoreSetup;
use YezzMedia\OpsSecurity\Support\SecretDefinitionRegistry;
use YezzMedia\OpsSecurity\Support\SecurityDecisionResolver;
use YezzMedia\OpsSecurity\Support\SecurityPayloadSanitizer;
use YezzMedia\OpsSecurity\Support\SecurityPostureSummaryBuilder;

class OpsSecurityServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-ops-security')
            ->hasConfigFile('ops-security')
            ->hasMigrations([
                '0001_create_ops_security_visibility_tables',
            ]);
    }

    public function packageRegistered(): void
    {
        $this->registerAuditWriter();
        $this->registerDoctorChecks();
        $this->registerInstallSteps();
        $this->registerResolvers();
        $this->registerSupport();
        $this->registerManager();
        $this->registerAction();
    }

    public function packageBooted(): void
    {
        $this->app->make(PlatformPackageRegistrar::class)
            ->register(new OpsSecurityPlatformPackage);

        $this->registerAuditListeners(
            $this->app->make(Dispatcher::class),
        );
    }

    private function registerAuditWriter(): void
    {
        $this->app->singleton(SecurityAuditWriter::class, fn () => $this->makeAuditWriter());
    }

    private function registerDoctorChecks(): void
    {
        $this->app->singleton(SslPostureCheck::class);
        $this->app->singleton(SshPostureCheck::class);

        $this->app->singleton(SecretHealthCheck::class);

        $this->app->singleton(SecurityConfigCheck::class);
        $this->app->singleton(SecurityResolverCheck::class);
        $this->app->singleton(LoginThrottleCheck::class);
        $this->app->singleton(PasswordConfirmationCheck::class);
        $this->app->singleton(PrivilegedMfaCheck::class);
        $this->app->singleton(SecurityDriftCheck::class);
        $this->app->singleton(SecurityPolicyConflictCheck::class);
    }

    private function registerInstallSteps(): void
    {
        $this->app->singleton(OpsSecurityVisibilityStoreSetup::class);
        $this->app->singleton(PublishSecurityConfigStep::class);
        $this->app->singleton(EnsureOpsSecurityVisibilityStoreReadyInstallStep::class);
        $this->app->singleton(VerifyOpsDependencyStep::class);
        $this->app->singleton(VerifyOpenSslExtensionStep::class);
    }

    private function registerResolvers(): void
    {
        $this->app->singleton(SslPostureResolver::class, fn () => new SslPostureResolver(
            $this->app->make(CertificateParser::class),
        ));

        $this->app->singleton(SshPostureResolver::class);
        $this->app->singleton(SecretHealthResolver::class, fn () => new SecretHealthResolver(
            $this->app->make(SecretDefinitionRegistry::class),
            $this->app->make(EntropyAnalyzer::class),
        ));

        $this->app->singleton(SecurityConfigResolver::class);
    }

    private function registerSupport(): void
    {
        $this->app->singleton(CertificateParser::class);
        $this->app->singleton(EntropyAnalyzer::class);
        $this->app->singleton(SecretDefinitionRegistry::class);
        $this->app->singleton(SecurityPayloadSanitizer::class);
        $this->app->singleton(SecurityDecisionResolver::class);

        $this->app->singleton(SecurityPostureSummaryBuilder::class);
        $this->app->singleton(SecurityRequestBroker::class, fn () => new DatabaseSecurityRequestBroker(
            storeSetup: $this->app->make(OpsSecurityVisibilityStoreSetup::class),
            securityRequests: $this->app->make(SecurityRequestRegistry::class),
            securityRequirements: $this->app->make(SecurityRequirementRegistry::class),
            payloadSanitizer: $this->app->make(SecurityPayloadSanitizer::class),
            decisionResolver: $this->app->make(SecurityDecisionResolver::class),
        ));
    }

    private function registerManager(): void
    {
        $this->app->singleton(OpsSecurityManager::class, fn () => new OpsSecurityManager(
            resolvers: $this->resolvers(),
            summaryBuilder: $this->app->make(SecurityPostureSummaryBuilder::class),
            securityRequests: $this->app->make(SecurityRequestRegistry::class),
            securityRequirements: $this->app->make(SecurityRequirementRegistry::class),
            requestBroker: $this->app->make(SecurityRequestBroker::class),
            cacheFactory: $this->app->make(CacheFactory::class),
            cacheEnabled: (bool) config('ops-security.cache.enabled', true),
            cacheStore: config('ops-security.cache.store'),
            cacheTtl: (int) config('ops-security.cache.ttl', 300),
            visibilityDisplayLimit: max(1, (int) config('ops-security.visibility.display_limit', 25)),
        ));
    }

    private function registerAction(): void
    {
        $this->app->singleton(RefreshSecurityPostureAction::class, fn () => new RefreshSecurityPostureAction(
            manager: $this->app->make(OpsSecurityManager::class),
            events: $this->app->make(Dispatcher::class),
        ));
    }

    private function registerAuditListeners(Dispatcher $events): void
    {
        $events->listen(
            SecurityPostureRefreshed::class,
            [WriteSecurityAuditEntry::class, 'handlePostureRefreshed'],
        );
    }

    private function makeAuditWriter(): SecurityAuditWriter
    {
        $driver = config('ops-security.audit.driver');

        if ($driver === null || $driver === 'null') {
            return new NullSecurityAuditWriter;
        }

        if ($driver !== 'activitylog') {
            throw new \InvalidArgumentException(
                "Unsupported ops-security audit driver [{$driver}]. Supported: null, activitylog.",
            );
        }

        if (! class_exists(ActivityLogger::class)) {
            throw new \RuntimeException(
                'The activitylog audit driver requires spatie/laravel-activitylog to be installed.',
            );
        }

        return new ActivityLogSecurityAuditWriter(
            $this->app->make(ActivityLogger::class),
        );
    }

    /**
     * @return array<int, SecurityPostureResolver>
     */
    private function resolvers(): array
    {
        return [
            $this->app->make(SslPostureResolver::class),
            $this->app->make(SshPostureResolver::class),
            $this->app->make(SecretHealthResolver::class),
            $this->app->make(SecurityConfigResolver::class),
        ];
    }
}
