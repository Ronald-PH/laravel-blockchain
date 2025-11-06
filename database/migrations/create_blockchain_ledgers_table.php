<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $tableName = config('blockchain.table_name', 'blockchain_ledgers');

        Schema::create($tableName, function (Blueprint $table) {
            $table->id();
            $table->string('table_name')->index();
            $table->unsignedBigInteger('record_id')->index();
            $table->string('data_hash', 64);
            $table->string('previous_hash', 64);
            $table->string('block_hash', 64)->unique();
            $table->text('signature');
            $table->timestamps();

            // Composite index for better query performance
            $table->index(['table_name', 'record_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $tableName = config('blockchain.table_name', 'blockchain_ledgers');
        Schema::dropIfExists($tableName);
    }
};