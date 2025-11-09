<?php

namespace RonaldPH\LaravelBlockchain\Models;

use Illuminate\Database\Eloquent\Model;

class ModelHasCertificate extends Model
{
    protected $table = 'model_has_certificates';

    protected $fillable = [
        'user_id',
        'certificate_path',
        'status',
    ];
}
