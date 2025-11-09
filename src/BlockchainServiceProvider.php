<?php

namespace RonaldPH\LaravelBlockchain;

use Illuminate\Support\ServiceProvider;

class BlockchainServiceProvider extends ServiceProvider
{
    /**
     * Register blockchain services and configuration.
     */
    public function register(): void
    {
        // Merge package configuration with application's config
        $this->mergeConfigFrom(
            __DIR__.'/../config/blockchain.php', 'blockchain'
        );

        // Register a singleton instance of BlockchainManager in the container
        $this->app->singleton('blockchain', function ($app) {
            return new BlockchainManager($app);
        });
    }

    /**
     * Bootstrap services such as publishing config, migrations, and commands.
     */
    public function boot(): void
    {
        // Publish package configuration to the application's config folder
        $this->publishes([
            __DIR__.'/../config/blockchain.php' => config_path('blockchain.php'),
        ], 'blockchain-config');

        // Publish database migrations
        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'blockchain-migrations');

        // Load package migrations automatically
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // Register console commands if running in CLI
        if ($this->app->runningInConsole()) {
            $this->commands([
                Console\VerifyChainCommand::class,
                Console\GenerateKeysCommand::class,
                Console\HealthCheckCommand::class,
            ]);
        }
    }
}
