<?php

namespace RonaldPH\LaravelBlockchain\Models;

use Illuminate\Database\Eloquent\Model;

class BlockchainRoot extends Model
{
    protected $fillable = [
        'table_name',
        'record_id',
        'merkle_root',
        'signature'
    ];
}
