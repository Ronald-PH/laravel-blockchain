<?php

namespace RonaldPH\LaravelBlockchain\Models;

use Illuminate\Database\Eloquent\Model;

class BlockchainLedger extends Model
{
    protected $fillable = [
        'nonce',
        'user_id',
        'table_name',
        'record_id',
        'data',
        'data_hash',
        'previous_hash',
        'block_hash',
        'signature',
        'with_user_certificate',
        'certificate_id',
        'default_certificate_id',
        'algorithm',
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'with_user_certificate' => 'boolean',
    ];

    public function getTable()
    {
        return config('blockchain.table_name', 'blockchain_ledgers');
    }

    public function previousBlock()
    {
        return $this->hasOne(self::class, 'block_hash', 'previous_hash')
            ->where('table_name', $this->table_name)
            ->where('record_id', $this->record_id);
    }

    public function nextBlock()
    {
        return $this->hasOne(self::class, 'previous_hash', 'block_hash')
            ->where('table_name', $this->table_name)
            ->where('record_id', $this->record_id);
    }

    public function scopeForRecord($query, string $tableName, int $recordId)
    {
        return $query->where('table_name', $tableName)
            ->where('record_id', $recordId);
    }

    public function getChain()
    {
        return static::where('table_name', $this->table_name)
            ->where('record_id', $this->record_id)
            ->orderBy('id', 'asc')
            ->get();
    }

    public function isGenesisBlock(): bool
    {
        return $this->previous_hash === config('blockchain.genesis_hash', '00000');
    }

    public function userCertificate() {
        return $this->hasOne(ModelHasCertificate::class, 'id', 'certificate_id');
    }
    public function defaultCertificate() {
        return $this->hasOne(BlockchainDefaultCertificate::class, 'id', 'default_certificate_id');
    }
}
