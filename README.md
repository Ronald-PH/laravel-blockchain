<p align="center">
  <img src="https://raw.githubusercontent.com/ronald-ph/laravel-blockchain/main/laravel-blockchain.png" alt="Laravel Blockchain Banner" width="100%" />
</p>

# ⚡ Laravel Blockchain

> A comprehensive Laravel package for implementing **blockchain ledger functionality** with **RSA-based digital signatures**, **Merkle root verification**, and **user-specific certificates** to ensure data integrity, provide an immutable **audit trail**, and enable advanced security features like fork detection and health monitoring.

![Packagist Version](https://img.shields.io/packagist/v/ronald-ph/laravel-blockchain?color=ff2d20&logo=laravel)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP](https://img.shields.io/badge/PHP-%5E8.1-blue?logo=php)
![Laravel](https://img.shields.io/badge/Laravel-%5E9.0-ff2d20?logo=laravel)

---
## ⚡ Upgrade Guide: v1.2.1 → v2.0.0
> is release introduces user-specific certificates, health checks, and enhanced chain verification.

## 1️⃣ Update Package
```bash
composer update ronald-ph/laravel-blockchain
```

## 2️⃣ Publish Updated Config & Migrations
```bash
php artisan vendor:publish --tag=blockchain-config
php artisan vendor:publish --tag=blockchain-migrations
php artisan migrate
```

## 3️⃣ Generate or Migrate Keys
```bash
php artisan blockchain:generate-keys --password=yourpassword
```

### Set in .env:
```env
BLOCKCHAIN_PRIVATE_KEY_PASSWORD=yourpassword
```

## 4️⃣ User Certificates (Optional)
```php
$block = Blockchain::createBlock(
    'users',
    $user->id,
    $user->only('id', 'name', 'email'),
    $user->id,
    request()->file('certificate')
);
```
v2.0.0 supports **user-specific PEM certificates**.
## 🚀 Features

- ✅ **Immutable blockchain records** for any Eloquent model
- ✅ **RSA-based digital signature verification** for cryptographic security
- ✅ **Chain integrity checks** and data tamper detection
- ✅ **Full audit trail** of all data changes with timestamps
- ✅ **Artisan commands** for key generation, chain verification, and health checks
- ✅ **Configurable hash algorithms** (SHA-256, SHA-512, etc.)
- ✅ **Support for custom cryptographic keys** and password-protected private keys
- ✅ **User-specific certificates** for multi-user applications and enhanced security
- ✅ **Merkle root verification** for additional integrity and hierarchical signing
- ✅ **Health check command** for comprehensive system monitoring
- ✅ **Fork detection** to prevent and identify chain manipulations
- ✅ **Comprehensive verification** (individual blocks, entire chains, data integrity)
- ✅ **Automatic chain verification** on block creation (configurable)
- ✅ **Multiple key management** (default certificates and user-specific certificates)
- ✅ **Exception handling** with custom BlockchainException for robust error management
- ✅ **Model relationships** for certificates and ledgers

---

## 📦 Installation

Install the package via Composer:

```bash
composer require ronald-ph/laravel-blockchain
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=blockchain-config
```

Publish and run the migrations:

```bash
php artisan vendor:publish --tag=blockchain-migrations
php artisan migrate
```

Generate cryptographic keys for signing blocks:

```bash
php artisan blockchain:generate-keys --password=yourpassword
```

Set the private key password in your `.env` file:

```env
BLOCKCHAIN_PRIVATE_KEY_PASSWORD=yourpassword
```

## ⚙️ Configuration

The configuration file is located at `config/blockchain.php`. Key settings include:

```php
return [
    'table_name' => 'blockchain_ledgers', // Main ledger table name
    'hash_algorithm' => 'sha256', // Hash algorithm for block hashing
    'keys_path' => storage_path('blockchain/keys'), // Path to store keys
    'private_key' => 'private.pem', // Default private key file
    'public_key' => 'public.pem', // Default public key file
    'private_key_password' => env('BLOCKCHAIN_PRIVATE_KEY_PASSWORD'), // Password for private key
    'genesis_hash' => '00000', // Genesis block hash
    'auto_verify' => false, // Auto-verify chain on block creation
    'with_blockchain_root' => false, // Enable Merkle root verification
    'master_private_key' => 'master_private.pem', // Master private key for Merkle roots
    'master_public_key' => 'master_public.pem', // Master public key for Merkle roots
    'master_private_key_password' => env('BLOCKCHAIN_MASTER_PRIVATE_KEY_PASSWORD'), // Master key password
];
```

## 🔑 Generate Keys

Generate RSA key pair for signing blockchain blocks:

```bash
# Generate 2048-bit keys with password
php artisan blockchain:generate-keys --password=yourpassword

# Generate 4096-bit keys
php artisan blockchain:generate-keys --bits=4096
```

Don't forget to set your password in `.env`:

```env
BLOCKCHAIN_PRIVATE_KEY_PASSWORD=yourpassword
```

## Usage

### 🧩 Basic Usage

```php
use RonaldPH\LaravelBlockchain\Facades\Blockchain;

// Create a user
$user = User::create([
    'name' => 'John Doe',
    'email' => 'john@example.com',
]);

// Create blockchain record
$block = Blockchain::createBlock(
    'users',                                      // table name
    $user->id,                                    // record ID
    $user->only('id', 'name', 'email')           // data to hash
);
```

### 📤 Using with Request (File Upload)

```php
use Illuminate\Http\Request;
use RonaldPH\LaravelBlockchain\Facades\Blockchain;

public function store(Request $request)
{
    $request->validate([
        'email' => 'required|email',
        'private_key' => 'required|file', // Optional for user-specific certificates
        'private_key_password' => 'required|string',
    ]);

    $user = User::create([
        'email' => $request->email,
    ]);

    // Create block with uploaded private key (user-specific certificate)
    $block = Blockchain::createBlock(
        'users',
        $user->id,
        json_encode($user->only('id', 'email', 'created_at')),
        $request->file('private_key'), // Optional: null for default certificate
        $request->private_key_password
    );

    return response()->json([
        'user' => $user,
        'block' => $block,
    ]);
}
```

### 🔄 Update & Chain Blocks

```php
// Update user
$user->update(['email' => 'newemail@example.com']);

// Create new blockchain block for the update
$block = Blockchain::createBlock(
    'users',
    $user->id,
    $user->only('id', 'email', 'updated_at')
);
```

## 🔍 Verification

### Verify a Block

```php
$result = Blockchain::verifyBlock($blockHash);

if ($result['valid']) {
    echo "Block is valid!";
} else {
    echo "Block verification failed: " . $result['message'];
}
```

### Verify Entire Chain

```php
$result = Blockchain::verifyChain('users', $userId);

if ($result['valid']) {
    echo "Chain is valid! Total blocks: " . $result['total_blocks'];
} else {
    echo "Chain verification failed!";
    print_r($result['invalid_blocks']);
}
```

### Verify Data Integrity

```php
$user = User::find($userId);

$result = Blockchain::verifyData(
    'users',
    $userId,
    $user->only('id', 'email', 'updated_at')
);

if ($result['valid']) {
    echo "Data has not been tampered with!";
} else {
    echo "Data tampering detected!";
}
```

### Get Blockchain History

```php
$history = Blockchain::getHistory('users', $userId);

foreach ($history as $block) {
    echo "Block #{$block->id} - {$block->created_at}\n";
    echo "Hash: {$block->block_hash}\n";
}
```

### 🔐 Using Custom Keys

```php
// Set custom private and public keys for a specific operation
$block = Blockchain::setPrivateKey('/path/to/private.pem', 'password')
    ->setPublicKey('/path/to/public.pem')
    ->createBlock('users', $userId, $data);

// Verify with custom public key
$result = Blockchain::setPublicKey('/path/to/public.pem')
    ->verifyBlock($blockHash);
```

### 🔸 User-Specific Certificates

```php
// Create block with user-specific certificate
$block = Blockchain::createBlock(
    'users',
    $userId,
    $data,
    $userId, // User ID for certificate lookup
    null // No file upload, uses stored certificate
);

// Update a user's certificate
Blockchain::updateModelCertificate(
    $userId,
    file_get_contents('/path/to/private.pem'),
    file_get_contents('/path/to/public.pem')
);
```

## 🧰 Artisan Commands

### Generate Keys

```bash
php artisan blockchain:generate-keys --password=yourpassword --bits=4096
```

### Verify Chain

```bash
php artisan blockchain:verify users 1
```

Output:
```
✓ Entire chain is valid
Total blocks verified: 5
```

### Health Check

Run comprehensive system health checks:

```bash
php artisan blockchain:health
```

Output:
```
🔍 Blockchain Health Check
═══════════════════════════════════════════════════

+----------------+-----------------------------+--------+--------------------------------+
| Category       | Check                       | Status | Details                        |
+----------------+-----------------------------+--------+--------------------------------+
| Environment    | PHP Version                 | ✓      | 8.2.0                          |
| Environment    | OpenSSL Extension           | ✓      | OK                             |
| Environment    | JSON Extension              | ✓      | OK                             |
| Environment    | App Environment             | ✓      | local                          |
| Keys           | Keys Directory Exists       | ✓      | /path/to/storage/blockchain    |
| Keys           | Private Key Exists          | ✓      | ✓                              |
| Keys           | Private Key Readable        | ✓      | ✓                              |
| Keys           | Private Key Format          | ✓      | Valid PEM                      |
| Keys           | Private Key Size            | ✓      | 1.8 KB                         |
| Keys           | Public Key Exists           | ✓      | ✓                              |
| Keys           | Public Key Readable         | ✓      | ✓                              |
| Keys           | Public Key Format           | ✓      | Valid PEM                      |
| Keys           | Private Key Password Set    | ✓      | Configured                     |
| Database       | Connection                  | ✓      | Connected                      |
| Database       | Database Name               | ✓      | laravel                        |
| Database       | Table Exists                | ✓      | blockchain_ledgers             |
| Database       | Table Schema                | ✓      | Valid                          |
| Database       | Indexes                     | ✓      | 4 indexes                      |
| Database       | Total Blocks                | ✓      | 1,234                          |
| Database       | Table Size                  | ✓      | 15.67 MB                       |
| Permissions    | Keys Directory              | ✓      | Writable (Perms: 0755)         |
| Permissions    | Logs Directory              | ✓      | Writable                       |
| Permissions    | Storage Directory           | ✓      | Writable                       |
| Configuration  | Hash Algorithm              | ✓      | sha256                         |
| Configuration  | Genesis Hash                | ✓      | 00000                          |
| Configuration  | Auto Verify                 | ✓      | Disabled                       |
| Configuration  | Keys Path                   | ✓      | /path/to/storage/blockchain    |
| Configuration  | Production Security         | ✓      | N/A (not production)           |
| Activity       | Last 24 Hours               | ✓      | 45 blocks                      |
| Activity       | Last 7 Days                 | ✓      | 312 blocks                     |
| Activity       | Last 30 Days                | ✓      | 1,156 blocks                   |
| Activity       | Latest Block                | ✓      | 2 hours ago                    |
| Activity       | Latest Block Hash           | ✓      | a1b2c3d4...                    |
| Activity       | Tables Tracked              | ✓      | 8                              |
| Chain Integrity| Sample Verification         | ✓      | 5/5 valid chains               |
| Chain Integrity| Orphaned Blocks             | ✓      | 0 blocks                       |
| Metrics        | Blocks Created              | ✓      | 1,234                          |
| Metrics        | Block Creation Failures     | ✓      | 0                              |
| Metrics        | Successful Verifications    | ✓      | 987                            |
| Metrics        | Invalid Signatures          | ✓      | 0                              |
| Metrics        | Hash Mismatch               | ✓      | 0                              |
| Metrics        | Chain Breaks                | ✓      | 0                              |
| Metrics        | Data Tampering Detected     | ✓      | 0                              |
| Disk Space     | Free Space                  | ✓      | 45.2 GB                        |
| Disk Space     | Total Space                 | ✓      | 100 GB                         |
| Disk Space     | Used                        | ✓      | 54.8%                          |
+----------------+-----------------------------+--------+--------------------------------+

═══════════════════════════════════════════════════
Summary: 45/45 checks passed
🎉 All checks passed! System is healthy.
```

Options:
```bash
# Detailed output
php artisan blockchain:health --detailed

# JSON output for monitoring systems
php artisan blockchain:health --json
```

## 🧠 Advanced Usage

### 🔸 Model Trait (Optional)

Create a trait to easily add blockchain to your models:

```php
namespace App\Traits;

use RonaldPH\LaravelBlockchain\Facades\Blockchain;

trait HasBlockchain
{
    public function createBlockchainRecord($data = null)
    {
        $data = $data ?? $this->toArray();

        return Blockchain::createBlock(
            $this->getTable(),
            $this->id,
            $data
        );
    }

    public function getBlockchainHistory()
    {
        return Blockchain::getHistory($this->getTable(), $this->id);
    }

    public function verifyBlockchain()
    {
        return Blockchain::verifyChain($this->getTable(), $this->id);
    }
}
```

Use in your model:

```php
class User extends Model
{
    use HasBlockchain;
}

// Usage
$user->createBlockchainRecord();
$history = $user->getBlockchainHistory();
$result = $user->verifyBlockchain();
```

### 🔸 Model Events (Auto-create blocks)

```php
class User extends Model
{
    protected static function boot()
    {
        parent::boot();

        static::created(function ($user) {
            Blockchain::createBlock(
                'users',
                $user->id,
                $user->only('id', 'email', 'created_at')
            );
        });

        static::updated(function ($user) {
            Blockchain::createBlock(
                'users',
                $user->id,
                $user->only('id', 'email', 'updated_at')
            );
        });
    }
}
```

### 🔸 Certificate Management

#### Default Certificate Management

```php
// Update default certificate for the application
$certificate = Blockchain::updateDefaultCertificate(
    file_get_contents('/path/to/private.pem'),
    file_get_contents('/path/to/public.pem')
);
```

#### User-Specific Certificates

```php
// Update user-specific certificate for multi-user security
$certificate = Blockchain::updateModelCertificate(
    $userId,
    file_get_contents('/path/to/private.pem'),
    file_get_contents('/path/to/public.pem')
);

// Retrieve a user's certificate
$userCertificate = Blockchain::getModelCertificate($userId);
```

### 🔸 Merkle Root Verification

Enable Merkle root verification in your config:

```php
'with_blockchain_root' => true,
'master_private_key' => 'master_private.pem',
'master_public_key' => 'master_public.pem',
'master_private_key_password' => env('BLOCKCHAIN_MASTER_PRIVATE_KEY_PASSWORD'),
```

Generate master keys for Merkle root signing:

```bash
# Generate master keys (separate from regular keys)
openssl genrsa -out master_private.pem 4096
openssl rsa -in master_private.pem -pubout -out master_public.pem
```

## 🌐 API Endpoints Example

```php
Route::prefix('blockchain')->group(function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::post('/verify/block/{hash}', [BlockchainController::class, 'verifyBlock']);
    Route::get('/verify/chain/{table}/{id}', [BlockchainController::class, 'verifyChain']);
    Route::get('/history/{table}/{id}', [BlockchainController::class, 'getHistory']);
    Route::get('/health', function () {
        return Artisan::call('blockchain:health --json');
    });
});
```

## ⚙️ How It Works

1. **Block Creation**: When you create a block, the package:
   - Hashes your data using the configured algorithm (e.g., SHA-256)
   - Chains it to the previous block's hash (or genesis hash for the first block)
   - Creates a unique block hash combining data, previous hash, and timestamp
   - Signs the block with RSA private key (default or user-specific)
   - Optionally signs with master key for Merkle root verification
   - Stores the block, signature, and metadata in the blockchain_ledgers table

2. **Verification**: When verifying:
   - Recalculates the block hash to ensure data integrity
   - Verifies the RSA digital signature using the corresponding public key
   - Checks chain continuity by validating previous hash links
   - Detects forks, tampering, or broken chains
   - For Merkle root enabled: Verifies hierarchical signatures

3. **Data Integrity**: The blockchain ensures:
   - Immutable records with cryptographic tamper detection
   - Complete chronological audit trail of all changes
   - Cryptographic proof of authenticity and non-repudiation
   - Tamper-evident history with fork detection capabilities
   - Support for both default and user-specific certificate management

## 🛡️ Security Recommendations

- 🔐 **Never commit private keys to version control** - Use .gitignore for key files
- 🧱 **Store keys securely** in `storage/blockchain/keys` with restricted permissions (e.g., 0700)
- 💪 **Use strong passwords** for private keys and rotate them periodically
- 💾 **Regularly back up** both cryptographic keys and blockchain ledger data
- 🔍 **Run health checks** (`php artisan blockchain:health`) regularly to monitor system integrity
- 🏛️ **Enable Merkle root verification** for hierarchical signing and enhanced security
- 👤 **Use user-specific certificates** in multi-user applications for isolated security
- 🔒 **Enable auto-verification** in config for real-time chain integrity checks
- 🚨 **Monitor for forks** using the verification commands to detect tampering attempts
- 📊 **Log and audit** all blockchain operations for compliance and security monitoring

## 🧪 Testing

```bash
composer test
```

## 📜 License

This package is open-sourced software licensed under the [MIT License](https://github.com/Ronald-PH/laravel-blockchain/?tab=MIT-1-ov-file)

## 💡 Credits

Developed by **Ronald PH**<br>
📦 [GitHub Repository](https://github.com/ronald-ph/laravel-blockchain)

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/ronald-ph/laravel-blockchain/issues).
