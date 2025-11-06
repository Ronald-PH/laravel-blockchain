<?php

namespace RonaldPH\LaravelBlockchain;

use Illuminate\Foundation\Application;
use Illuminate\Http\UploadedFile;
use RonaldPH\LaravelBlockchain\Models\BlockchainLedger;
use RonaldPH\LaravelBlockchain\Exceptions\BlockchainException;

class BlockchainManager
{
    protected Application $app;
    protected ?string $privateKeyPath = null;
    protected ?string $publicKeyPath = null;
    protected ?string $privateKeyPassword = null;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * Set custom private key
     */
    public function setPrivateKey(string $path, ?string $password = null): self
    {
        $this->privateKeyPath = $path;
        $this->privateKeyPassword = $password;
        return $this;
    }

    /**
     * Set custom public key
     */
    public function setPublicKey(string $path): self
    {
        $this->publicKeyPath = $path;
        return $this;
    }

    /**
     * Get private key path
     */
    protected function getPrivateKeyPath(): string
    {
        if ($this->privateKeyPath) {
            return $this->privateKeyPath;
        }

        $keysPath = config('blockchain.keys_path');
        $privateKey = config('blockchain.private_key');

        return $keysPath . '/' . $privateKey;
    }

    /**
     * Get public key path
     */
    protected function getPublicKeyPath(): string
    {
        if ($this->publicKeyPath) {
            return $this->publicKeyPath;
        }

        $keysPath = config('blockchain.keys_path');
        $publicKey = config('blockchain.public_key');

        return $keysPath . '/' . $publicKey;
    }

    /**
     * Get private key password
     */
    protected function getPrivateKeyPassword(): ?string
    {
        return $this->privateKeyPassword ?? config('blockchain.private_key_password');
    }

    /**
     * Sign block data with private key
     */
    public function signBlock(string $data, $privateKey = null, ?string $password = null): string
    {
        if ($privateKey instanceof UploadedFile) {
            $privateKeyContent = file_get_contents($privateKey->getRealPath());
            $password = $password ?? $this->getPrivateKeyPassword();
        } elseif (is_string($privateKey)) {
            $privateKeyContent = file_get_contents($privateKey);
        } else {
            $privateKeyContent = file_get_contents($this->getPrivateKeyPath());
            $password = $this->getPrivateKeyPassword();
        }

        $key = openssl_pkey_get_private($privateKeyContent, $password);

        if (!$key) {
            throw new BlockchainException('Failed to load private key: ' . openssl_error_string());
        }

        $success = openssl_sign($data, $signature, $key, config('blockchain.signature_algorithm'));
        openssl_free_key($key);

        if (!$success) {
            throw new BlockchainException('Failed to sign data: ' . openssl_error_string());
        }

        return base64_encode($signature);
    }

    /**
     * Create a new blockchain block
     */
    public function createBlock(string $tableName, int $recordId, $data, $privateKey = null, ?string $password = null): BlockchainLedger
    {
        // Auto verify if enabled
        if (config('blockchain.auto_verify')) {
            $verification = $this->verifyChain($tableName, $recordId);
            if (!$verification['valid']) {
                throw new BlockchainException('Chain verification failed: ' . $verification['message']);
            }
        }

        $blockchain = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'DESC')
            ->first();

        $dataString = is_array($data) || is_object($data) ? json_encode($data) : $data;
        $hashAlgorithm = config('blockchain.hash_algorithm', 'sha256');

        // Hash Data
        $dataHash = hash($hashAlgorithm, $dataString);
        $previousHash = $blockchain->block_hash ?? config('blockchain.genesis_hash', '00000');
        $blockHash = hash($hashAlgorithm, $dataHash . $previousHash);

        $signatureData = $dataHash . $previousHash . $blockHash;
        $signature = $this->signBlock($signatureData, $privateKey, $password);

        $block = BlockchainLedger::create([
            'table_name' => $tableName,
            'record_id' => $recordId,
            'data_hash' => $dataHash,
            'previous_hash' => $previousHash,
            'block_hash' => $blockHash,
            'signature' => $signature,
        ]);

        return $block;
    }

    /**
     * Verify a blockchain block
     */
    public function verifyBlock(string $blockHash, $publicKey = null): array
    {
        $block = BlockchainLedger::where('block_hash', $blockHash)->first();

        if (!$block) {
            return [
                'valid' => false,
                'message' => 'Block not found'
            ];
        }

        $hashAlgorithm = config('blockchain.hash_algorithm', 'sha256');

        // 1. Verify block hash integrity
        $calculatedHash = hash($hashAlgorithm, $block->data_hash . $block->previous_hash);
        if ($calculatedHash !== $block->block_hash) {
            return [
                'valid' => false,
                'message' => 'Block hash mismatch',
                'block' => $block
            ];
        }

        // 2. Verify signature with public key
        $signatureData = $block->data_hash . $block->previous_hash . $block->block_hash;
        $signature = base64_decode($block->signature);

        if ($publicKey instanceof UploadedFile) {
            $publicKeyContent = file_get_contents($publicKey->getRealPath());
        } elseif (is_string($publicKey)) {
            $publicKeyContent = file_get_contents($publicKey);
        } else {
            $publicKeyContent = file_get_contents($this->getPublicKeyPath());
        }

        $key = openssl_pkey_get_public($publicKeyContent);

        if (!$key) {
            throw new BlockchainException('Failed to load public key: ' . openssl_error_string());
        }

        $isValidSignature = openssl_verify($signatureData, $signature, $key, config('blockchain.signature_algorithm'));
        openssl_free_key($key);

        if ($isValidSignature !== 1) {
            return [
                'valid' => false,
                'message' => 'Invalid signature',
                'block' => $block
            ];
        }

        // 3. Verify chain integrity
        $genesisHash = config('blockchain.genesis_hash', '00000');
        if ($block->previous_hash !== $genesisHash) {
            $previousBlock = BlockchainLedger::where('table_name', $block->table_name)
                ->where('record_id', $block->record_id)
                ->where('block_hash', $block->previous_hash)
                ->first();

            if (!$previousBlock) {
                return [
                    'valid' => false,
                    'message' => 'Previous block not found - chain broken',
                    'block' => $block
                ];
            }
        }

        return [
            'valid' => true,
            'message' => 'Block is valid',
            'block' => $block
        ];
    }

    /**
     * Verify entire blockchain for a specific record
     */
    public function verifyChain(string $tableName, int $recordId, $publicKey = null): array
    {
        $blocks = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'ASC')
            ->get();

        if ($blocks->isEmpty()) {
            return [
                'valid' => true,
                'message' => 'No blocks found - nothing to verify'
            ];
        }

        $invalidBlocks = [];

        foreach ($blocks as $block) {
            $verification = $this->verifyBlock($block->block_hash, $publicKey);

            if (!$verification['valid']) {
                $invalidBlocks[] = [
                    'block_id' => $block->id,
                    'block_hash' => $block->block_hash,
                    'reason' => $verification['message']
                ];
            }
        }

        if (!empty($invalidBlocks)) {
            return [
                'valid' => false,
                'message' => 'Chain verification failed',
                'invalid_blocks' => $invalidBlocks
            ];
        }

        return [
            'valid' => true,
            'message' => 'Entire chain is valid',
            'total_blocks' => $blocks->count()
        ];
    }

    /**
     * Get blockchain history for a record
     */
    public function getHistory(string $tableName, int $recordId)
    {
        return BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'ASC')
            ->get();
    }

    /**
     * Verify data hasn't been tampered with
     */
    public function verifyData(string $tableName, int $recordId, $currentData): array
    {
        $latestBlock = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'DESC')
            ->first();

        if (!$latestBlock) {
            return [
                'valid' => false,
                'message' => 'No blockchain record found'
            ];
        }

        $dataString = is_array($currentData) || is_object($currentData) ? json_encode($currentData) : $currentData;
        $hashAlgorithm = config('blockchain.hash_algorithm', 'sha256');
        $currentDataHash = hash($hashAlgorithm, $dataString);

        if ($currentDataHash !== $latestBlock->data_hash) {
            return [
                'valid' => false,
                'message' => 'Data has been tampered with',
                'expected_hash' => $latestBlock->data_hash,
                'actual_hash' => $currentDataHash
            ];
        }

        return [
            'valid' => true,
            'message' => 'Data integrity verified'
        ];
    }

    /**
     * Get the latest block for a record
     */
    public function getLatestBlock(string $tableName, int $recordId): ?BlockchainLedger
    {
        return BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'DESC')
            ->first();
    }
}