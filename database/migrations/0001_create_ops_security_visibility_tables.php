<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ops_security_requests', static function (Blueprint $table): void {
            $table->id();
            $table->string('request_key')->index();
            $table->string('package')->index();
            $table->string('domain')->index();
            $table->string('control')->index();
            $table->string('scope')->index();
            $table->string('requested_level');
            $table->string('requested_enforcement_mode');
            $table->string('status')->index();
            $table->json('payload_preview');
            $table->string('source')->nullable();
            $table->string('actor')->nullable();
            $table->timestamp('recorded_at')->index();
            $table->timestamps();
        });

        Schema::create('ops_security_decisions', static function (Blueprint $table): void {
            $table->id();
            $table->string('request_key')->index();
            $table->string('package')->index();
            $table->string('domain')->index();
            $table->string('control')->index();
            $table->string('scope')->index();
            $table->string('requested_level');
            $table->string('requested_enforcement_mode');
            $table->string('effective_level');
            $table->string('effective_enforcement_mode');
            $table->string('status')->index();
            $table->json('payload_preview');
            $table->boolean('has_conflict')->default(false)->index();
            $table->text('conflict_reason')->nullable();
            $table->string('source')->nullable();
            $table->string('actor')->nullable();
            $table->timestamp('recorded_at')->index();
            $table->timestamps();
        });

        Schema::create('ops_security_runtime_evidence', static function (Blueprint $table): void {
            $table->id();
            $table->string('request_key')->index();
            $table->string('package')->index();
            $table->string('domain')->index();
            $table->string('control')->index();
            $table->string('scope')->index();
            $table->string('status')->index();
            $table->json('payload_preview');
            $table->string('source')->nullable();
            $table->string('actor')->nullable();
            $table->timestamp('recorded_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ops_security_runtime_evidence');
        Schema::dropIfExists('ops_security_decisions');
        Schema::dropIfExists('ops_security_requests');
    }
};
