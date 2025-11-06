<?php

namespace RonaldPH\LaravelBlockchain\Console;

use Illuminate\Console\Command;
use RonaldPH\LaravelBlockchain\Facades\Blockchain;

class VerifyChainCommand extends Command
{
    protected $signature = 'blockchain:verify {table_name} {record_id}';
    protected $description = 'Verify the blockchain integrity for a specific record';

    public function handle()
    {
        $tableName = $this->argument('table_name');
        $recordId = $this->argument('record_id');

        $this->info("Verifying blockchain for {$tableName} record #{$recordId}...");

        try {
            $result = Blockchain::verifyChain($tableName, $recordId);

            if ($result['valid']) {
                $this->info("✓ {$result['message']}");
                $this->info("Total blocks verified: {$result['total_blocks']}");
            } else {
                $this->error("✗ {$result['message']}");
                
                if (isset($result['invalid_blocks'])) {
                    $this->error("Invalid blocks found:");
                    foreach ($result['invalid_blocks'] as $invalid) {
                        $this->error("  - Block #{$invalid['block_id']}: {$invalid['reason']}");
                    }
                }
            }

            return $result['valid'] ? 0 : 1;
        } catch (\Exception $e) {
            $this->error("Verification failed: {$e->getMessage()}");
            return 1;
        }
    }
}