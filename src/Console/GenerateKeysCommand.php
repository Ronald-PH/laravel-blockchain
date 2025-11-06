<?php

namespace RonaldPH\LaravelBlockchain\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class GenerateKeysCommand extends Command
{
    protected $signature = 'blockchain:generate-keys 
                            {--password= : Password to encrypt the private key}
                            {--bits=2048 : Key size in bits (2048 or 4096)}';
    
    protected $description = 'Generate RSA key pair for blockchain signing';

    public function handle()
    {
        $password = $this->option('password') ?: $this->secret('Enter password for private key (optional)');
        $bits = (int) $this->option('bits');

        if (!in_array($bits, [2048, 4096])) {
            $this->error('Key size must be 2048 or 4096 bits');
            return 1;
        }

        $this->info("Generating {$bits}-bit RSA key pair...");

        $keysPath = config('blockchain.keys_path');

        // Create keys directory if it doesn't exist
        if (!File::exists($keysPath)) {
            File::makeDirectory($keysPath, 0755, true);
            $this->info("Created keys directory: {$keysPath}");
        }

        // Generate private key
        $config = [
            "digest_alg" => "sha256",
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        
        if (!$res) {
            $this->error('Failed to generate key pair: ' . openssl_error_string());
            return 1;
        }

        // Export private key
        $privateKeyPath = $keysPath . '/' . config('blockchain.private_key', 'private.pem');
        openssl_pkey_export_to_file($res, $privateKeyPath, $password ?: null);

        // Export public key
        $publicKeyDetails = openssl_pkey_get_details($res);
        $publicKeyPath = $keysPath . '/' . config('blockchain.public_key', 'public.pem');
        File::put($publicKeyPath, $publicKeyDetails["key"]);

        openssl_free_key($res);

        $this->info("✓ Private key saved to: {$privateKeyPath}");
        $this->info("✓ Public key saved to: {$publicKeyPath}");

        if ($password) {
            $this->warn("Don't forget to set BLOCKCHAIN_PRIVATE_KEY_PASSWORD in your .env file!");
        }

        return 0;
    }
}