<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blockchain_roots', function (Blueprint $table) {
            $table->id();
            $table->string('table_name');
            $table->unsignedBigInteger('record_id')->nullable();
            $table->string('merkle_root')->nullable();
            $table->text('signature'); // signed by master key
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blockchain_roots');
    }
};
