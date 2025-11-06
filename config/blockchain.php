<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Blockchain Table Name
    |--------------------------------------------------------------------------
    |
    | The name of the table that will store blockchain ledger records.
    |
    */
    'table_name' => env('BLOCKCHAIN_TABLE_NAME', 'blockchain_ledgers'),

    /*
    |--------------------------------------------------------------------------
    | Hash Algorithm
    |--------------------------------------------------------------------------
    |
    | The hashing algorithm to use for block hashing.
    | Supported: 'sha256', 'sha512', 'md5' (not recommended)
    |
    */
    'hash_algorithm' => env('BLOCKCHAIN_HASH_ALGORITHM', 'sha256'),

    /*
    |--------------------------------------------------------------------------
    | Signature Algorithm
    |--------------------------------------------------------------------------
    |
    | The OpenSSL signature algorithm to use.
    | Supported: OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA512
    |
    */
    'signature_algorithm' => OPENSSL_ALGO_SHA256,

    /*
    |--------------------------------------------------------------------------
    | Keys Storage Path
    |--------------------------------------------------------------------------
    |
    | The path where cryptographic keys are stored.
    |
    */
    'keys_path' => storage_path('blockchain/keys'),

    /*
    |--------------------------------------------------------------------------
    | Default Private Key
    |--------------------------------------------------------------------------
    |
    | Path to the default private key file (relative to keys_path).
    |
    */
    'private_key' => env('BLOCKCHAIN_PRIVATE_KEY', 'private.pem'),

    /*
    |--------------------------------------------------------------------------
    | Default Public Key
    |--------------------------------------------------------------------------
    |
    | Path to the default public key file (relative to keys_path).
    |
    */
    'public_key' => env('BLOCKCHAIN_PUBLIC_KEY', 'public.pem'),

    /*
    |--------------------------------------------------------------------------
    | Private Key Password
    |--------------------------------------------------------------------------
    |
    | Password for the private key encryption.
    |
    */
    'private_key_password' => env('BLOCKCHAIN_PRIVATE_KEY_PASSWORD', null),

    /*
    |--------------------------------------------------------------------------
    | Genesis Block Hash
    |--------------------------------------------------------------------------
    |
    | The hash used for the genesis block (first block in chain).
    |
    */
    'genesis_hash' => '00000',

    /*
    |--------------------------------------------------------------------------
    | Auto Verify Chain
    |--------------------------------------------------------------------------
    |
    | Automatically verify the blockchain integrity before creating new blocks.
    |
    */
    'auto_verify' => env('BLOCKCHAIN_AUTO_VERIFY', false),
];