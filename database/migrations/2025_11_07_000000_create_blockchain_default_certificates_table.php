<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blockchain_default_certificates', function (Blueprint $table) {
            $table->id();
            $table->string('public_key_path');
            $table->string('private_key_path');
            $table->integer('status')->max(2)->default(1);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('model_has_certificates');
    }
};
