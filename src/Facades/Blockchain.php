<?php

namespace RonaldPH\LaravelBlockchain\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \RonaldPH\LaravelBlockchain\BlockchainManager setPrivateKey(string $path, ?string $password = null)
 * @method static \RonaldPH\LaravelBlockchain\BlockchainManager setPublicKey(string $path)
 * @method static string signBlock(string $data, $privateKey = null, ?string $password = null)
 * @method static \RonaldPH\LaravelBlockchain\Models\BlockchainLedger createBlock(string $tableName, int $recordId, $data, $privateKey = null, ?string $password = null)
 * @method static array verifyBlock(string $blockHash, $publicKey = null)
 * @method static array verifyChain(string $tableName, int $recordId, $publicKey = null)
 * @method static \Illuminate\Support\Collection getHistory(string $tableName, int $recordId)
 * @method static array verifyData(string $tableName, int $recordId, $currentData)
 * @method static \RonaldPH\LaravelBlockchain\Models\BlockchainLedger|null getLatestBlock(string $tableName, int $recordId)
 *
 * @see \RonaldPH\LaravelBlockchain\BlockchainManager
 */
class Blockchain extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'blockchain';
    }
}