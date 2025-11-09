<?php

namespace RonaldPH\LaravelBlockchain\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Facade for the BlockchainManager service.
 *
 * Provides a static interface for common blockchain operations such as:
 * signing data, creating blocks, verifying blocks/chain, retrieving history,
 * and managing default or model-specific certificates.
 *
 * @method static \RonaldPH\LaravelBlockchain\BlockchainManager setPrivateKey(string $path, ?string $password = null)
 * @method static \RonaldPH\LaravelBlockchain\BlockchainManager setPublicKey(string $path)
 * @method static string signBlock(string $data, $privateKey = null, ?string $password = null)
 * @method static \RonaldPH\LaravelBlockchain\Models\BlockchainLedger createBlock(
 *     string $tableName,
 *     int $recordId,
 *     $data,
 *     $userIdOrPrivateKey = null,
 *     $certificateFile = null
 * )
 * @method static array verifyBlock(string $blockHash, $publicKey = null)
 * @method static array verifyChain(string $tableName, int $recordId, $publicKey = null)
 * @method static \Illuminate\Support\Collection getHistory(string $tableName, int $recordId)
 * @method static array verifyData(string $tableName, int $recordId, $currentData)
 * @method static \RonaldPH\LaravelBlockchain\Models\BlockchainLedger|null getLatestBlock(string $tableName, int $recordId)
 * @method static \RonaldPH\LaravelBlockchain\Models\BlockchainDefaultCertificate updateDefaultCertificate($privateKeyFile, $publicKeyFile)
 * @method static \RonaldPH\LaravelBlockchain\Models\ModelHasCertificate updateModelCertificate($modelType, $modelId, $privateKeyFile, $publicKeyFile)
 *
 * @see \RonaldPH\LaravelBlockchain\BlockchainManager
 */
class Blockchain extends Facade
{
    /**
     * Get the service container binding for the facade.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'blockchain';
    }
}
