<?php
namespace RonaldPH\LaravelBlockchain;

use Illuminate\Foundation\Application;
use Illuminate\Support\Str;
use RonaldPH\LaravelBlockchain\Models\BlockchainLedger;
use RonaldPH\LaravelBlockchain\Exceptions\BlockchainException;
use RonaldPH\LaravelBlockchain\Facades\Blockchain;
use RonaldPH\LaravelBlockchain\Models\BlockchainDefaultCertificate;
use RonaldPH\LaravelBlockchain\Models\BlockchainRoot;
use RonaldPH\LaravelBlockchain\Models\ModelHasCertificate;

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
     * Assign a custom private key path and optional password.
     *
     * @param  string       $path      Full path to the private key file.
     * @param  string|null  $password  Password if the private key is encrypted.
     * @return self
     */
    public function setPrivateKey(string $path, ?string $password = null): self
    {
        $this->privateKeyPath = $path;
        $this->privateKeyPassword = $password;
        return $this;
    }

    /**
     * Assign a custom public key path for verification.
     *
     * @param  string  $path  Full path to the public key file.
     * @return self
     */
    public function setPublicKey(string $path): self
    {
        $this->publicKeyPath = $path;
        return $this;
    }

    /**
     * Get the active private key path.
     *
     * Returns the custom private key if set, otherwise falls back
     * to the currently active default certificate or the system default.
     *
     * @return string
     */
    protected function getPrivateKeyPath(): string
    {
        if ($this->privateKeyPath) {
            return $this->privateKeyPath;
        }

        $default_certificate = BlockchainDefaultCertificate::where('status', 1)->first();

        if ($default_certificate) {
            $privateKey = $default_certificate->private_key_path;
        } else {
            $privateKey = config('blockchain.keys_path') . '/' . config('blockchain.private_key');
        }

        return storage_path($privateKey);
    }

    /**
     * Get the appropriate public key path for verifying a block.
     *
     * Selects between user-specific certificate, default certificate,
     * or system default public key depending on the block configuration.
     *
     * @param  BlockchainLedger  $block
     * @return string
     */
    protected function getPublicKeyPath(BlockchainLedger $block): string
    {
        if ($this->publicKeyPath) {
            return $this->publicKeyPath;
        }

        if ($block->with_user_certificate == 1) {
            $publicKeyPath = $block->userCertificate->public_key_path;
        } elseif ($block->with_user_certificate == 0) {
            $publicKeyPath = $block->defaultCertificate->public_key_path;
        } else {
            $publicKeyPath = config('blockchain.keys_path') . '/' . config('blockchain.public_key');
        }

        return storage_path($publicKeyPath);
    }

    /**
     * Retrieve the password for the private key.
     *
     * Returns the custom password if set, otherwise uses
     * the system configuration.
     *
     * @return string|null
     */
    protected function getPrivateKeyPassword(): ?string
    {
        return $this->privateKeyPassword ?? config('blockchain.private_key_password');
    }

    /**
     * Sign a block of data using a private key.
     *
     * Uses a user-specific certificate if available, otherwise falls
     * back to the system default key. Returns a Base64-encoded signature.
     *
     * @param  string       $data       Data to sign.
     * @param  string|null  $privateKey Optional path to a private key.
     * @param  string|null  $password   Optional password for the key.
     * @param  string|null  $user_id    ID of the user owning the certificate.
     * @return string
     * @throws BlockchainException
     */
    public function signBlock(string $data, $privateKey = null, ?string $password = null, ?string $user_id = null): string
    {
        $user_certificate = ModelHasCertificate::where('user_id', $user_id)->where('status', 1)->first();

        if ($user_certificate) {
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
     * Create a new block in the blockchain.
     *
     * Computes hashes, generates a signature using either the user
     * certificate or the default system key, and stores the block
     * as a ledger entry. Optionally verifies the chain before appending.
     *
     * @param  string       $tableName  Database table linked to the block.
     * @param  int          $recordId   ID of the record.
     * @param  mixed        $data       Block data (array, object, or string).
     * @param  int|null     $user_id    Optional user ID creating the block.
     * @param  string|null  $privateKey Optional private key for signing.
     * @param  string|null  $password   Optional password for the private key.
     * @return BlockchainLedger|array
     */
    public function createBlock(string $tableName, int $recordId, $data, ?int $user_id = null, $privateKey = null, ?string $password = null)
    {

        $timestamp = $timestamp ?? now()->toDateTimeString();
        if (config('blockchain.auto_verify')) {

            $verification = $this->verifyChain($tableName, $recordId);
            if (!$verification['valid']) {
                return $verification;
            }
        }
        $blockchain = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'DESC')
            ->first();

        if ($blockchain) {
            $existingChildren = BlockchainLedger::where('previous_hash', $blockchain->block_hash)
                ->where('table_name', $tableName)
                ->where('record_id', $recordId)
                ->count();

            if ($existingChildren > 0) {
                return [
                    'valid' => false,
                    'message' => 'Fork detected: another block already references this parent hash. Please try again.'
                ];
            }
        }

        $dataString = is_array($data) || is_object($data) ? json_encode($data) : $data;
        $hashAlgorithm = config('blockchain.hash_algorithm', 'sha256');

        $dataHash = hash($hashAlgorithm, $dataString);
        $previousHash = $blockchain->block_hash ?? config('blockchain.genesis_hash', '00000');
        $blockHash = hash($hashAlgorithm, hash($hashAlgorithm, $dataHash . $previousHash . $timestamp));

        $signatureData = $dataString . $dataHash . $previousHash . $blockHash . $hashAlgorithm;

        $with_certificate = ModelHasCertificate::where('user_id', $user_id)->where('status', 1)->first();
        $default_certificate = BlockchainDefaultCertificate::where('status', 1)->first();
        if ($with_certificate) {
            $signature = $this->signBlock($signatureData, $privateKey, $password, $user_id);
        } else {
            $signature = $this->signBlock($signatureData, $default_certificate->private_key_path, config('blockchain.private_key_password'));
        }

        $block = BlockchainLedger::create([
            'nonce' => 'BLOCK-' . date('YmdHis') . '-' . strtoupper(substr(uniqid(), -5)),
            'user_id' => $user_id,
            'table_name' => $tableName,
            'record_id' => $recordId,
            'data' => json_encode($data),
            'data_hash' => $dataHash,
            'previous_hash' => $previousHash,
            'block_hash' => $blockHash,
            'signature' => $signature,
            'with_user_certificate' => $with_certificate ? true : false,
            'certificate_id' => $with_certificate ? $with_certificate->id : null,
            'default_certificate_id' => !$with_certificate && $default_certificate ? $default_certificate->id : null,
            'algorithm' => $hashAlgorithm,
        ]);
        config('blockchain.with_merkle_root') ? $this->updateMerkleRoot($tableName, $recordId) : '';

        return $block;
    }

    /**
     * Verify the signature and integrity of a single block.
     *
     * Recomputes the data hash and uses the public key to confirm
     * authenticity. Returns true if valid, false otherwise.
     *
     * @param  BlockchainLedger  $block
     * @return bool
     * @throws BlockchainException
     */
    public function verifyBlock(BlockchainLedger $block): bool
    {

        $computedHash = $block->data . $block->data_hash . $block->previous_hash . $block->block_hash . $block->algorithm;

        $publicKeyPath = $this->getPublicKeyPath($block);
        if ($block->with_user_certificate == 1) {
            $certificate = ModelHasCertificate::where('id', $block->certificate_id)->first();
            if ($certificate && file_exists($certificate->public_key_path) && $block->with_user_certificate == 1) {
                $publicKeyPath = $certificate->public_key_path;
            }
        }

        if (!file_exists($publicKeyPath)) {
            throw new BlockchainException("Public key file not found: {$publicKeyPath}");
        }

        $publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));

        if (!$publicKey) {
            throw new BlockchainException("Invalid public key format at {$publicKeyPath}");
        }

        $result = openssl_verify($computedHash, base64_decode($block->signature), $publicKey, OPENSSL_ALGO_SHA256);
        openssl_free_key($publicKey);

        return $result === 1;
    }

    /**
     * Verify the entire blockchain for a specific record.
     *
     * Checks every block’s signature and optionally validates
     * the Merkle root for overall chain integrity.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @return array
     */
    public function verifyChain(string $tableName, int $recordId): array
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

        if(config('blockchain.with_merkle_root')) {
            $merkle_root = BlockchainRoot::where('table_name', $tableName)->where('record_id', $recordId)->first();
            $verify_root = $this->verifyMerkleRoot($tableName, $recordId);
            if (!$verify_root) {
                return [
                    'valid' => false,
                    'message' => 'Blockchain tampering detected: Merkle root verification failed. One or more blocks may have been altered.',
                ];
            }
        }

        $invalidBlocks = [];

        foreach ($blocks as $block) {
            $verification = $this->verifyBlock($block);
            if (!$verification) {
                $invalidBlocks[] = [
                    'block_id' => $block->id,
                    'block_hash' => $block->block_hash,
                    'reason' => 'Data possibly tampered',
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
     * Get all blockchain history for a specific record.
     *
     * Returns a chronological collection of all blocks for the record.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @return \Illuminate\Support\Collection
     */
    public function getHistory(string $tableName, int $recordId)
    {
        return BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'ASC')
            ->get();
    }

    /**
     * Verify that the current data matches the latest block.
     *
     * Useful for confirming data integrity without altering the chain.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @param  mixed   $currentData
     * @return array
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
     * Retrieve the latest block for a given record.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @return BlockchainLedger|null
     */
    public function getLatestBlock(string $tableName, int $recordId): ?BlockchainLedger
    {
        return BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'DESC')
            ->first();
    }

    /**
     * Compute the Merkle root from an array of block hashes.
     *
     * Combines hashes pairwise recursively until a single root is produced.
     *
     * @param  array  $hashes
     * @return string
     */
    private function computeMerkleRoot(array $hashes): string
    {
        if (empty($hashes)) return '';

        while (count($hashes) > 1) {
            $temp = [];

            for ($i = 0; $i < count($hashes); $i += 2) {
                if (isset($hashes[$i + 1])) {
                    $temp[] = hash('sha256', $hashes[$i] . $hashes[$i + 1]);
                } else {
                    // Duplicate last hash if odd number of hashes
                    $temp[] = hash('sha256', $hashes[$i] . $hashes[$i]);
                }
            }

            $hashes = $temp;
        }

        return $hashes[0];
    }

    /**
     * Update the Merkle root and sign it with the master private key.
     *
     * Provides an additional integrity check across all blocks.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @return void
     */
    public function updateMerkleRoot(string $tableName, int $recordId)
    {
        $blocks = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'ASC')
            ->pluck('block_hash')
            ->toArray();

        if (empty($blocks)) return;

        $merkleRoot = $this->computeMerkleRoot($blocks);

        $masterPrivateKey = file_get_contents(config('blockchain.master_private_key'));
        $password = config('blockchain.master_private_key_password');
        openssl_sign($merkleRoot, $signature, openssl_pkey_get_private($masterPrivateKey, $password), OPENSSL_ALGO_SHA256);

        BlockchainRoot::updateOrCreate(
            ['table_name' => $tableName, 'record_id' => $recordId],
            ['merkle_root' => $merkleRoot, 'signature' => base64_encode($signature)]
        );
    }

    /**
     * Verify the Merkle root for a given record.
     *
     * Confirms the root signature and recomputes the root to detect tampering.
     *
     * @param  string  $tableName
     * @param  int     $recordId
     * @return bool
     */
    public function verifyMerkleRoot(string $tableName, int $recordId): bool
    {
        $root = BlockchainRoot::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->first();

        if (!$root) {
            $blocks = BlockchainLedger::where('table_name', $tableName)
                ->where('record_id', $recordId)
                ->orderBy('id', 'ASC')
                ->pluck('block_hash')
                ->toArray();

            if (empty($blocks)) return false;

            $merkleRoot = $this->computeMerkleRoot($blocks);

            $masterPrivateKey = file_get_contents(config('blockchain.master_private_key'));
            $password = config('blockchain.master_private_key_password');
            openssl_sign($merkleRoot, $signature, openssl_pkey_get_private($masterPrivateKey, $password), OPENSSL_ALGO_SHA256);

            $root = BlockchainRoot::create([
                'table_name' => $tableName,
                'record_id' => $recordId,
                'merkle_root' => $merkleRoot,
                'signature' => base64_encode($signature)
            ]);
        };

        $blocks = BlockchainLedger::where('table_name', $tableName)
            ->where('record_id', $recordId)
            ->orderBy('id', 'ASC')
            ->pluck('block_hash')
            ->toArray();

        $computedRoot = $this->computeMerkleRoot($blocks);
        $masterPublicKey = file_get_contents(config('blockchain.master_public_key'));

        $verified = openssl_verify(
            $computedRoot,
            base64_decode($root->signature),
            openssl_pkey_get_public($masterPublicKey),
            OPENSSL_ALGO_SHA256
        );

        return $verified === 1 && $computedRoot === $root->merkle_root;
    }
    public function updateDefaultCertificate($privateKeyFile, $publicKeyFile)
    {
        $keysPath = config('blockchain.keys_path');

        // Ensure the keys directory exists
        if (!is_dir($keysPath)) {
            mkdir($keysPath, 0755, true);
        }

        // Generate random file names
        $privateKeyFilename = 'private_' . Str::random(16) . rand(0, 999) . '.pem';
        $publicKeyFilename  = 'public_' . Str::random(16) . rand(0, 999) . '.pem';

        // Full paths
        $privateKeyPath = $keysPath . '/' . $privateKeyFilename;
        $publicKeyPath  = $keysPath . '/' . $publicKeyFilename;

        // Save the keys
        file_put_contents($privateKeyPath, $privateKeyFile);
        file_put_contents($publicKeyPath, $publicKeyFile);

        // Deactivate previous certificate if exists
        $previousCert = BlockchainDefaultCertificate::where('status', 1)->first();
        if ($previousCert) {
            $previousCert->update(['status' => 2]);
        }

        // Create new default certificate
        $defaultCert = BlockchainDefaultCertificate::create([
            'private_key_path' => $privateKeyPath,
            'public_key_path'  => $publicKeyPath,
            'status'           => 1, // active
        ]);

        return $defaultCert;
    }
    public function updateModelCertificate($modelId, $privateKeyFile, $publicKeyFile)
    {
        $keysPath = config('blockchain.keys_path');

        // Ensure the keys directory exists
        if (!is_dir($keysPath)) {
            mkdir($keysPath, 0755, true);
        }

        // Generate random file names
        $privateKeyFilename = 'private_' . Str::random(16) . $modelId . '.pem';
        $publicKeyFilename  = 'public_' . Str::random(16) . $modelId . '.pem';

        // Full paths
        $privateKeyPath = $keysPath . '/' . $privateKeyFilename;
        $publicKeyPath  = $keysPath . '/' . $publicKeyFilename;

        // Save the keys
        file_put_contents($privateKeyPath, $privateKeyFile);
        file_put_contents($publicKeyPath, $publicKeyFile);

        // Deactivate previous active certificate for this model
        $previousCert = ModelHasCertificate::where('user_id', $modelId)
            ->where('status', 1)
            ->first();

        if ($previousCert) {
            $previousCert->update(['status' => 2]);
        }

        // Create new certificate
        $newCert = ModelHasCertificate::create([
            'user_id'         => $modelId,
            'private_key_path' => $privateKeyPath,
            'public_key_path'  => $publicKeyPath,
            'status'           => 1, // active
        ]);

        return $newCert;
    }
}
