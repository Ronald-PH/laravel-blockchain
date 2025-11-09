<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Blockchain Ledger Table
    |--------------------------------------------------------------------------
    |
    | The table that stores blockchain ledger entries.
    | You can override this in .env via BLOCKCHAIN_TABLE_NAME.
    |
    */
    'table_name' => env('BLOCKCHAIN_TABLE_NAME', 'blockchain_ledgers'),

    /*
    |--------------------------------------------------------------------------
    | Hashing Algorithm
    |--------------------------------------------------------------------------
    |
    | The algorithm used to generate block hashes.
    | Supported: 'sha256', 'sha512', 'md5' (md5 not recommended).
    |
    */
    'hash_algorithm' => env('BLOCKCHAIN_HASH_ALGORITHM', 'sha256'),

    /*
    |--------------------------------------------------------------------------
    | Signature Algorithm
    |--------------------------------------------------------------------------
    |
    | OpenSSL algorithm used for signing blockchain data.
    | Options: OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA512.
    |
    */
    'signature_algorithm' => OPENSSL_ALGO_SHA256,

    /*
    |--------------------------------------------------------------------------
    | Keys Storage Directory
    |--------------------------------------------------------------------------
    |
    | The default location for blockchain keys (private/public).
    |
    */
    'keys_path' => storage_path('blockchain/keys'),

    /*
    |--------------------------------------------------------------------------
    | Default Private Key
    |--------------------------------------------------------------------------
    |
    | File name of the default private key relative to keys_path.
    | Used if no user certificate is assigned.
    |
    */
    'private_key' => env('BLOCKCHAIN_PRIVATE_KEY', 'private4.pem'),

    /*
    |--------------------------------------------------------------------------
    | Default Public Key
    |--------------------------------------------------------------------------
    |
    | File name of the default public key relative to keys_path.
    | Used to verify blockchain data without user certificate.
    |
    */
    'public_key' => env('BLOCKCHAIN_PUBLIC_KEY', 'public4.pem'),

    /*
    |--------------------------------------------------------------------------
    | Private Key Password
    |--------------------------------------------------------------------------
    |
    | Password for the default private key if encrypted.
    | Can be set in .env as BLOCKCHAIN_PRIVATE_KEY_PASSWORD.
    |
    */
    'private_key_password' => env('BLOCKCHAIN_PRIVATE_KEY_PASSWORD', null),

    /*
    |--------------------------------------------------------------------------
    | Genesis Block Hash
    |--------------------------------------------------------------------------
    |
    | Initial block hash for the blockchain.
    |
    */
    'genesis_hash' => '00000',

    /*
    |--------------------------------------------------------------------------
    | Save Algorithm Metadata
    |--------------------------------------------------------------------------
    |
    | Whether each block stores its hashing algorithm.
    | Useful if you might change system default in the future.
    |
    */
    'save_algorithm' => false,

    /*
    |--------------------------------------------------------------------------
    | Automatic Chain Verification
    |--------------------------------------------------------------------------
    |
    | If true, verifies the chain integrity before adding a new block.
    |
    */
    'auto_verify' => env('BLOCKCHAIN_AUTO_VERIFY', true),

    /*
    |--------------------------------------------------------------------------
    | Blockchain Root Configuration
    |--------------------------------------------------------------------------
    |
    | Enable Merkle root signing with a master key pair.
    |
    */
    'with_blockchain_root' => env('WITH_BLOCKCHAIN_ROOT', false),
    'master_private_key' => env('MASTER_PRIVATE_KEY', null),
    'master_private_key_password' => env('MASTER_PRIVATE_KEY_PASSWORD', null),
    'master_public_key' => env('MASTER_PUBLIC_KEY', null),

];
