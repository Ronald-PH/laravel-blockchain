<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blockchain_ledgers', function (Blueprint $table) {
            $table->id();
            $table->string('nonce')->nullable();
            $table->unsignedBigInteger('user_id')->nullable();
            $table->string('table_name')->index();
            $table->unsignedBigInteger('record_id')->index();
            $table->json('data')->nullable();
            $table->string('data_hash', 64);
            $table->string('previous_hash', 64);
            $table->string('block_hash', 64)->unique();
            $table->text('signature');
            $table->boolean('with_user_certificate')->default(false);
            $table->unsignedBigInteger('certificate_id')->nullable();
            $table->unsignedBigInteger('default_certificate_id')->nullable();
            $table->string('algorithm')->nullable();
            $table->timestamps();

            $table->index(['table_name', 'record_id']);

            $table->foreign('user_id')->references('id')->on('users');
            $table->foreign('certificate_id')->references('id')->on('model_has_certificates');
            $table->foreign('default_certificate_id')->references('id')->on('blockchain_default_certificates');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blockchain_ledgers');
    }
};
