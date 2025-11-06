<?php

namespace RonaldPH\LaravelBlockchain;

use Illuminate\Support\ServiceProvider;

class BlockchainServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/blockchain.php', 'blockchain'
        );

        $this->app->singleton('blockchain', function ($app) {
            return new BlockchainManager($app);
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/blockchain.php' => config_path('blockchain.php'),
        ], 'blockchain-config');

        // Publish migrations
        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'blockchain-migrations');

        // Load migrations
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                Console\VerifyChainCommand::class,
                Console\GenerateKeysCommand::class,
            ]);
        }
    }
}