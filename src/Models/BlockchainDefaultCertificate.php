<?php

namespace RonaldPH\LaravelBlockchain\Models;

use Illuminate\Database\Eloquent\Model;

class BlockchainDefaultCertificate extends Model
{
    protected $table = 'blockchain_default_certificates';

    protected $fillable = [
        'public_key_path',
        'private_key_path',
        'status',
    ];
}
