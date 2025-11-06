<p align="center">
  <img src="https://raw.githubusercontent.com/ronald-ph/laravel-blockchain/main/laravel-blockchain.png" alt="Laravel Blockchain Banner" width="100%" />
</p>

# ⚡ Laravel Blockchain

> A Laravel package for implementing **blockchain ledger functionality** with **digital signatures** to ensure data integrity and provide an immutable **audit trail**.

![Packagist Version](https://img.shields.io/packagist/v/ronald-ph/laravel-blockchain?color=ff2d20&logo=laravel)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP](https://img.shields.io/badge/PHP-%5E8.1-blue?logo=php)
![Laravel](https://img.shields.io/badge/Laravel-%5E9.0-ff2d20?logo=laravel)

---

## 🚀 Features

- ✅ Immutable blockchain records for any model  
- ✅ RSA-based **digital signature verification**  
- ✅ Chain integrity and data tamper detection  
- ✅ Full audit trail of data changes  
- ✅ Artisan commands for key generation and chain verification  
- ✅ Configurable **hash algorithms** (SHA-256, SHA-512, etc.)  
- ✅ Support for **custom cryptographic keys**

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

## ⚙️ Configuration

The configuration file is located at `config/blockchain.php`. Key settings include:

```php
return [
    'table_name' => 'blockchain_ledgers',
    'hash_algorithm' => 'sha256',
    'keys_path' => storage_path('blockchain/keys'),
    'private_key' => 'private.pem',
    'public_key' => 'public.pem',
    'private_key_password' => env('BLOCKCHAIN_PRIVATE_KEY_PASSWORD'),
    'genesis_hash' => '00000',
    'auto_verify' => false,
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
        'private_key' => 'required|file',
        'private_key_password' => 'required|string',
    ]);

    $user = User::create([
        'email' => $request->email,
    ]);

    // Create block with uploaded private key
    $block = Blockchain::createBlock(
        'users',
        $user->id,
        json_encode($user->only('id', 'email', 'created_at')),
        $request->file('private_key'),
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
// Set custom private and public keys
$block = Blockchain::setPrivateKey('/path/to/private.pem', 'password')
    ->setPublicKey('/path/to/public.pem')
    ->createBlock('users', $userId, $data);

// Verify with custom public key
$result = Blockchain::setPublicKey('/path/to/public.pem')
    ->verifyBlock($blockHash);
```

## 🧰 Artisan Commands

### Verify Chain

```bash
php artisan blockchain:verify users 1
```

Output:
```
✓ Entire chain is valid
Total blocks verified: 5
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

## 🌐 API Endpoints Example

```php
Route::prefix('blockchain')->group(function () {
    Route::post('/users', [UserController::class, 'store']);
    Route::post('/verify/block/{hash}', [BlockchainController::class, 'verifyBlock']);
    Route::get('/verify/chain/{table}/{id}', [BlockchainController::class, 'verifyChain']);
    Route::get('/history/{table}/{id}', [BlockchainController::class, 'getHistory']);
});
```

## ⚙️ How It Works

1. **Block Creation**: When you create a block, the package:
   - Hashes your data using SHA-256
   - Chains it to the previous block's hash
   - Creates a unique block hash
   - Signs the block with your private key
   - Stores everything in the database

2. **Verification**: When verifying:
   - Recalculates the block hash to ensure integrity
   - Verifies the digital signature using the public key
   - Checks the chain links to previous blocks
   - Detects any tampering or broken chains

3. **Data Integrity**: The blockchain ensures:
   - Data cannot be modified without detection
   - Complete audit trail of all changes
   - Cryptographic proof of authenticity
   - Tamper-evident history

## 🛡️ Security Recommendations

- 🔐 Never commit private keys to version control
- 🧱 Store keys in **storage/** with correct permissions
- 💪 Use strong passwords and rotate keys periodically
- 💾 Regularly back up both keys and ledger data

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
