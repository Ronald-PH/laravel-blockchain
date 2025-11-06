<?php

namespace RonaldPH\LaravelBlockchain\Models;

use Illuminate\Database\Eloquent\Model;

class BlockchainLedger extends Model
{
    protected $fillable = [
        'table_name',
        'record_id',
        'data_hash',
        'previous_hash',
        'block_hash',
        'signature',
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Get the table name from config
     */
    public function getTable()
    {
        return config('blockchain.table_name', 'blockchain_ledgers');
    }

    /**
     * Get the previous block in the chain
     */
    public function previousBlock()
    {
        return $this->hasOne(BlockchainLedger::class, 'block_hash', 'previous_hash')
            ->where('table_name', $this->table_name)
            ->where('record_id', $this->record_id);
    }

    /**
     * Get the next block in the chain
     */
    public function nextBlock()
    {
        return $this->hasOne(BlockchainLedger::class, 'previous_hash', 'block_hash')
            ->where('table_name', $this->table_name)
            ->where('record_id', $this->record_id);
    }

    /**
     * Scope to get blocks for a specific table and record
     */
    public function scopeForRecord($query, string $tableName, int $recordId)
    {
        return $query->where('table_name', $tableName)
            ->where('record_id', $recordId);
    }

    /**
     * Get all blocks in chronological order for this record
     */
    public function getChain()
    {
        return static::where('table_name', $this->table_name)
            ->where('record_id', $this->record_id)
            ->orderBy('id', 'asc')
            ->get();
    }

    /**
     * Check if this is a genesis block
     */
    public function isGenesisBlock(): bool
    {
        $genesisHash = config('blockchain.genesis_hash', '00000');
        return $this->previous_hash === $genesisHash;
    }
}