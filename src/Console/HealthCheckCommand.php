<?php

namespace RonaldPH\LaravelBlockchain\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;
use RonaldPH\LaravelBlockchain\Models\BlockchainLedger;
use RonaldPH\LaravelBlockchain\Facades\Blockchain;

class HealthCheckCommand extends Command
{
    protected $signature = 'blockchain:health
                            {--json : Output as JSON}
                            {--detailed : Show detailed information}';

    protected $description = 'Comprehensive blockchain system health check';

    protected array $results = [];

    public function handle()
    {
        if (!$this->option('json')) {
            $this->info('🔍 Blockchain Health Check');
            $this->info('═══════════════════════════════════════════════════');
            $this->newLine();
        }

        // Run all health checks
        $this->checkEnvironment();
        $this->checkKeys();
        $this->checkDatabase();
        $this->checkPermissions();
        $this->checkConfiguration();
        $this->checkActivity();
        $this->checkChainIntegrity();
        $this->checkMetrics();
        $this->checkDiskSpace();

        // Output results
        if ($this->option('json')) {
            $this->outputJson();
        } else {
            $this->outputTable();
            $this->outputSummary();
        }

        return $this->hasFailures() ? 1 : 0;
    }

    protected function checkEnvironment(): void
    {
        $this->startCheck('Environment');

        $checks = [
            'PHP Version' => version_compare(PHP_VERSION, '8.1.0', '>='),
            'OpenSSL Extension' => extension_loaded('openssl'),
            'JSON Extension' => extension_loaded('json'),
            'App Environment' => app()->environment(),
        ];

        foreach ($checks as $name => $status) {
            if (is_bool($status)) {
                $this->addResult('Environment', $name, $status, $status ? 'OK' : 'Missing');
            } else {
                $this->addResult('Environment', $name, true, $status);
            }
        }

        $this->endCheck('Environment');
    }

    protected function checkKeys(): void
    {
        $this->startCheck('Cryptographic Keys');

        $keysPath = config('blockchain.keys_path');
        $privateKeyFile = config('blockchain.private_key');
        $publicKeyFile = config('blockchain.public_key');

        $privateKeyPath = $keysPath . '/' . $privateKeyFile;
        $publicKeyPath = $keysPath . '/' . $publicKeyFile;

        // Check keys directory exists
        $dirExists = is_dir($keysPath);
        $this->addResult('Keys', 'Keys Directory Exists', $dirExists, $dirExists ? $keysPath : 'Not found');

        if (!$dirExists) {
            $this->addResult('Keys', 'Fix', false, "Run: mkdir -p {$keysPath}");
            $this->endCheck('Keys');
            return;
        }

        // Check private key
        $privateExists = file_exists($privateKeyPath);
        $this->addResult('Keys', 'Private Key Exists', $privateExists, $privateExists ? '✓' : 'Not found');

        if ($privateExists) {
            $privateReadable = is_readable($privateKeyPath);
            $this->addResult('Keys', 'Private Key Readable', $privateReadable, $privateReadable ? '✓' : 'Permission denied');

            // Check key format
            $privateContent = file_get_contents($privateKeyPath);
            $validFormat = str_contains($privateContent, '-----BEGIN');
            $this->addResult('Keys', 'Private Key Format', $validFormat, $validFormat ? 'Valid PEM' : 'Invalid format');

            // Check key size
            $keySize = filesize($privateKeyPath);
            $this->addResult('Keys', 'Private Key Size', true, $this->formatBytes($keySize));
        }

        // Check public key
        $publicExists = file_exists($publicKeyPath);
        $this->addResult('Keys', 'Public Key Exists', $publicExists, $publicExists ? '✓' : 'Not found');

        if ($publicExists) {
            $publicReadable = is_readable($publicKeyPath);
            $this->addResult('Keys', 'Public Key Readable', $publicReadable, $publicReadable ? '✓' : 'Permission denied');

            // Check key format
            $publicContent = file_get_contents($publicKeyPath);
            $validFormat = str_contains($publicContent, '-----BEGIN');
            $this->addResult('Keys', 'Public Key Format', $validFormat, $validFormat ? 'Valid PEM' : 'Invalid format');
        }

        // Check key password
        $hasPassword = !empty(config('blockchain.private_key_password'));
        $this->addResult('Keys', 'Private Key Password Set', $hasPassword, $hasPassword ? 'Configured' : 'Not set');

        if (!$privateExists || !$publicExists) {
            $this->addResult('Keys', 'Fix', false, 'Run: php artisan blockchain:generate-keys');
        }

        $this->endCheck('Keys');
    }

    protected function checkDatabase(): void
    {
        $this->startCheck('Database');

        try {
            // Test connection
            DB::connection()->getPdo();
            $this->addResult('Database', 'Connection', true, 'Connected');

            // Check database name
            $dbName = DB::connection()->getDatabaseName();
            $this->addResult('Database', 'Database Name', true, $dbName);

            // Check if table exists
            $tableName = config('blockchain.table_name', 'blockchain_ledgers');
            $tableExists = DB::getSchemaBuilder()->hasTable($tableName);
            $this->addResult('Database', 'Table Exists', $tableExists, $tableExists ? $tableName : 'Not found');

            if (!$tableExists) {
                $this->addResult('Database', 'Fix', false, 'Run: php artisan migrate');
                $this->endCheck('Database');
                return;
            }

            // Check table columns
            $expectedColumns = ['id', 'table_name', 'record_id', 'data_hash', 'previous_hash', 'block_hash', 'signature', 'created_at', 'updated_at'];
            $actualColumns = DB::getSchemaBuilder()->getColumnListing($tableName);
            $missingColumns = array_diff($expectedColumns, $actualColumns);

            $this->addResult('Database', 'Table Schema', empty($missingColumns), empty($missingColumns) ? 'Valid' : 'Missing: ' . implode(', ', $missingColumns));

            // Check indexes
            $indexes = DB::select("SHOW INDEX FROM {$tableName}");
            $indexCount = count($indexes);
            $this->addResult('Database', 'Indexes', $indexCount > 0, "{$indexCount} indexes");

            // Get table statistics
            $totalBlocks = BlockchainLedger::count();
            $this->addResult('Database', 'Total Blocks', true, number_format($totalBlocks));

            $tableSize = DB::select("
                SELECT
                    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
                FROM information_schema.TABLES
                WHERE table_schema = ?
                AND table_name = ?
            ", [$dbName, $tableName]);

            if (!empty($tableSize)) {
                $this->addResult('Database', 'Table Size', true, $tableSize[0]->size_mb . ' MB');
            }

        } catch (\Exception $e) {
            $this->addResult('Database', 'Connection', false, $e->getMessage());
        }

        $this->endCheck('Database');
    }

    protected function checkPermissions(): void
    {
        $this->startCheck('File Permissions');

        $keysPath = config('blockchain.keys_path');

        // Check keys directory permissions
        if (is_dir($keysPath)) {
            $dirPerms = substr(sprintf('%o', fileperms($keysPath)), -4);
            $dirWritable = is_writable($keysPath);
            $this->addResult('Permissions', 'Keys Directory', $dirWritable, "Writable (Perms: {$dirPerms})");
        } else {
            $this->addResult('Permissions', 'Keys Directory', false, 'Directory not found');
        }

        // Check log directory
        $logPath = storage_path('logs');
        $logWritable = is_writable($logPath);
        $this->addResult('Permissions', 'Logs Directory', $logWritable, $logWritable ? 'Writable' : 'Not writable');

        // Check storage directory
        $storagePath = storage_path('blockchain');
        if (!is_dir($storagePath)) {
            mkdir($storagePath, 0755, true);
        }
        $storageWritable = is_writable($storagePath);
        $this->addResult('Permissions', 'Storage Directory', $storageWritable, $storageWritable ? 'Writable' : 'Not writable');

        $this->endCheck('Permissions');
    }

    protected function checkConfiguration(): void
    {
        $this->startCheck('Configuration');

        // Hash algorithm
        $hashAlgo = config('blockchain.hash_algorithm', 'sha256');
        $validAlgos = ['sha256', 'sha512'];
        $validHash = in_array($hashAlgo, $validAlgos);
        $this->addResult('Configuration', 'Hash Algorithm', $validHash, $hashAlgo . ($validHash ? '' : ' (weak)'));

        // Genesis hash
        $genesisHash = config('blockchain.genesis_hash', '00000');
        $this->addResult('Configuration', 'Genesis Hash', true, $genesisHash);

        // Auto verify
        $autoVerify = config('blockchain.auto_verify', false);
        $this->addResult('Configuration', 'Auto Verify', true, $autoVerify ? 'Enabled' : 'Disabled');

        // Keys path
        $keysPath = config('blockchain.keys_path');
        $this->addResult('Configuration', 'Keys Path', true, $keysPath);

        // Security checks
        $isProd = app()->environment('production');
        $hasPassword = !empty(config('blockchain.private_key_password'));

        if ($isProd && !$hasPassword) {
            $this->addResult('Configuration', 'Production Security', false, 'Private key password not set in production!');
        } else {
            $this->addResult('Configuration', 'Production Security', true, $isProd ? 'Password protected' : 'N/A (not production)');
        }

        $this->endCheck('Configuration');
    }

    protected function checkActivity(): void
    {
        $this->startCheck('Recent Activity');

        try {
            // Last 24 hours
            $last24h = BlockchainLedger::where('created_at', '>', now()->subDay())->count();
            $this->addResult('Activity', 'Last 24 Hours', true, number_format($last24h) . ' blocks');

            // Last 7 days
            $last7days = BlockchainLedger::where('created_at', '>', now()->subDays(7))->count();
            $this->addResult('Activity', 'Last 7 Days', true, number_format($last7days) . ' blocks');

            // Last 30 days
            $last30days = BlockchainLedger::where('created_at', '>', now()->subDays(30))->count();
            $this->addResult('Activity', 'Last 30 Days', true, number_format($last30days) . ' blocks');

            // Latest block
            $latestBlock = BlockchainLedger::orderBy('id', 'desc')->first();
            if ($latestBlock) {
                $this->addResult('Activity', 'Latest Block', true, $latestBlock->created_at->diffForHumans());
                $this->addResult('Activity', 'Latest Block Hash', true, substr($latestBlock->block_hash, 0, 16) . '...');
            } else {
                $this->addResult('Activity', 'Latest Block', false, 'No blocks found');
            }

            // Unique tables
            $uniqueTables = BlockchainLedger::distinct('table_name')->count('table_name');
            $this->addResult('Activity', 'Tables Tracked', true, $uniqueTables);

        } catch (\Exception $e) {
            $this->addResult('Activity', 'Error', false, $e->getMessage());
        }

        $this->endCheck('Activity');
    }

    protected function checkChainIntegrity(): void
    {
        $this->startCheck('Chain Integrity');

        try {
            // Sample random chains for verification
            $sampleSize = 5;
            $samples = BlockchainLedger::select('table_name', 'record_id')
                ->distinct()
                ->inRandomOrder()
                ->limit($sampleSize)
                ->get();

            if ($samples->isEmpty()) {
                $this->addResult('Chain Integrity', 'Sample Check', true, 'No chains to verify');
                $this->endCheck('Chain Integrity');
                return;
            }

            $validChains = 0;
            $totalChains = $samples->count();
            $brokenChains = [];

            foreach ($samples as $sample) {
                try {
                    $result = Blockchain::verifyChain($sample->table_name, $sample->record_id);
                    if ($result['valid']) {
                        $validChains++;
                    } else {
                        $brokenChains[] = "{$sample->table_name}:{$sample->record_id}";
                    }
                } catch (\Exception $e) {
                    $brokenChains[] = "{$sample->table_name}:{$sample->record_id} (Error: {$e->getMessage()})";
                }
            }

            $allValid = $validChains === $totalChains;
            $this->addResult(
                'Chain Integrity',
                'Sample Verification',
                $allValid,
                "{$validChains}/{$totalChains} valid chains"
            );

            if (!empty($brokenChains)) {
                $this->addResult('Chain Integrity', 'Broken Chains', false, implode(', ', $brokenChains));
            }

            // Check for orphaned blocks
            $orphanedBlocks = DB::table(config('blockchain.table_name', 'blockchain_ledgers'))
                ->whereNotExists(function ($query) {
                    $table = config('blockchain.table_name', 'blockchain_ledgers');
                    $query->select(DB::raw(1))
                        ->from("{$table} as b2")
                        ->whereColumn('b2.block_hash', "{$table}.previous_hash");
                })
                ->where('previous_hash', '!=', config('blockchain.genesis_hash', '00000'))
                ->count();

            $this->addResult('Chain Integrity', 'Orphaned Blocks', $orphanedBlocks === 0, $orphanedBlocks . ' blocks');

        } catch (\Exception $e) {
            $this->addResult('Chain Integrity', 'Error', false, $e->getMessage());
        }

        $this->endCheck('Chain Integrity');
    }

    protected function checkMetrics(): void
    {
        $this->startCheck('System Metrics');

        $metrics = [
            'blocks_created',
            'block_creation_failures',
            'successful_verifications',
            'invalid_signatures',
            'hash_mismatch',
            'chain_breaks',
            'data_tampering_detected',
        ];

        foreach ($metrics as $metric) {
            $key = "blockchain:metrics:{$metric}:" . now()->format('Y-m-d');
            $value = Cache::get($key, 0);

            $isCritical = in_array($metric, ['chain_breaks', 'data_tampering_detected']);
            $status = $isCritical ? $value === 0 : true;

            $this->addResult('Metrics', ucwords(str_replace('_', ' ', $metric)), $status, number_format($value));
        }

        $this->endCheck('Metrics');
    }

    protected function checkDiskSpace(): void
    {
        $this->startCheck('Disk Space');

        $keysPath = config('blockchain.keys_path');

        if (function_exists('disk_free_space')) {
            $freeSpace = disk_free_space($keysPath);
            $totalSpace = disk_total_space($keysPath);
            $usedSpace = $totalSpace - $freeSpace;
            $usedPercent = ($usedSpace / $totalSpace) * 100;

            $this->addResult('Disk Space', 'Free Space', true, $this->formatBytes($freeSpace));
            $this->addResult('Disk Space', 'Total Space', true, $this->formatBytes($totalSpace));
            $this->addResult('Disk Space', 'Used', $usedPercent < 90, number_format($usedPercent, 1) . '%');
        } else {
            $this->addResult('Disk Space', 'Check', false, 'disk_free_space() not available');
        }

        $this->endCheck('Disk Space');
    }

    protected function startCheck(string $category): void
    {
        if (!$this->option('json') && $this->option('detailed')) {
            $this->info("Checking {$category}...");
        }
    }

    protected function endCheck(string $category): void
    {
        if (!$this->option('json') && $this->option('detailed')) {
            $this->newLine();
        }
    }

    protected function addResult(string $category, string $check, bool $status, string $message): void
    {
        $this->results[] = [
            'category' => $category,
            'check' => $check,
            'status' => $status,
            'message' => $message,
        ];
    }

    protected function outputTable(): void
    {
        $headers = ['Category', 'Check', 'Status', 'Details'];
        $rows = [];

        foreach ($this->results as $result) {
            $icon = $result['status'] ? '✓' : '✗';
            $rows[] = [
                $result['category'],
                $result['check'],
                $icon,
                $result['message'],
            ];
        }

        $this->table($headers, $rows);
    }

    protected function outputSummary(): void
    {
        $total = count($this->results);
        $passed = count(array_filter($this->results, fn($r) => $r['status']));
        $failed = $total - $passed;

        $this->newLine();
        $this->info("═══════════════════════════════════════════════════");
        $this->info("Summary: {$passed}/{$total} checks passed");

        if ($failed > 0) {
            $this->error("{$failed} checks failed");
            $this->newLine();
            $this->warn('⚠️  Please address the failed checks above.');
        } else {
            $this->info('🎉 All checks passed! System is healthy.');
        }
    }

    protected function outputJson(): void
    {
        $summary = [
            'timestamp' => now()->toIso8601String(),
            'status' => $this->hasFailures() ? 'unhealthy' : 'healthy',
            'total_checks' => count($this->results),
            'passed' => count(array_filter($this->results, fn($r) => $r['status'])),
            'failed' => count(array_filter($this->results, fn($r) => !$r['status'])),
            'checks' => $this->results,
        ];

        $this->line(json_encode($summary, JSON_PRETTY_PRINT));
    }

    protected function hasFailures(): bool
    {
        return !empty(array_filter($this->results, fn($r) => !$r['status']));
    }

    protected function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= pow(1024, $pow);

        return round($bytes, 2) . ' ' . $units[$pow];
    }
}
