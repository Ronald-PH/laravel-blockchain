<p align="center">
  <img src="https://raw.githubusercontent.com/ronald-ph/laravel-blockchain/main/laravel-blockchain.png" alt="Laravel Blockchain Banner" width="100%" />
</p>
Secure your Laravel app's data with Laravel Blockchain. Create immutable, cryptographically signed records, maintain a complete audit trail, and detect tampering automatically.

# Laravel Blockchain – Give Your Database a Tamper-Proof Memory

![Packagist Version](https://img.shields.io/packagist/v/ronald-ph/laravel-blockchain?color=ff2d20&logo=laravel)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP](https://img.shields.io/badge/PHP-%5E8.1-blue?logo=php)
![Laravel](https://img.shields.io/badge/Laravel-%5E9.0-ff2d20?logo=laravel)

> Ever wondered if someone's been messing with your database records? This package brings blockchain-style immutability to your Laravel app, so you'll always know if your data has been tampered with. Think of it as a tamper-evident seal for your most important records.

## Why You Might Want This

Let's be real: traditional databases are great, but they don't keep a reliable history of changes, and anyone with access can modify records without leaving a trace. Laravel Blockchain solves this by:

- **Creating an unbreakable chain of records** – Each entry cryptographically links to the previous one, making tampering practically impossible
- **Proving data authenticity** – Digital signatures ensure records haven't been altered since creation
- **Building a complete audit trail** – Perfect for compliance, financial records, or any data you can't afford to lose trust in
- **Detecting forks and manipulations** – The system automatically spots if someone tries to rewrite history

**Real-world use cases:**
- Financial transactions and invoices
- Medical records and patient histories
- Legal documents and contracts
- Inventory and supply chain tracking
- Voting systems and election results
- Certificate issuance and verification
- Any data where integrity matters more than convenience

---

## Getting Started (The Easy Way)

### Step 1: Install the Package

```bash
composer require ronald-ph/laravel-blockchain
```

### Step 2: Publish Configuration and Migrations

```bash
# Publish the config file
php artisan vendor:publish --tag=blockchain-config

# Publish and run migrations
php artisan vendor:publish --tag=blockchain-migrations
php artisan migrate
```

This creates a `blockchain_ledgers` table that will store your immutable records.

### Step 3: Generate Your Security Keys

Think of these like the master keys to your blockchain. You'll need them to sign and verify blocks.

```bash
php artisan blockchain:generate-keys --password=your-secure-password
```

Then add the password to your `.env` file:

```env
BLOCKCHAIN_PRIVATE_KEY_PASSWORD=your-secure-password
```

**That's it!** You're ready to start creating tamper-proof records.

---

## Your First Blockchain Record (In 5 Lines)

Let's say you want to create a tamper-proof record whenever a user is created:

```php
use RonaldPH\LaravelBlockchain\Facades\Blockchain;

// Create a user (the normal way)
$user = User::create([
    'name' => 'Jane Doe',
    'email' => 'jane@example.com',
]);

// Lock it into the blockchain (the secure way)
$block = Blockchain::createBlock(
    'users',                                    // Which table
    $user->id,                                  // Which record
    $user->only('id', 'name', 'email')         // What data to protect
);
```

Done! That user record is now part of an immutable chain. If anyone tries to modify it later, you'll know.

---

## How Does It Actually Work?

Don't worry, you don't need to understand blockchain to use this. But here's the simple version:

1. **You create a record** → The package hashes your data
2. **It links to the previous record** → Creating a chain
3. **It signs everything with cryptography** → Making it tamper-proof
4. **You can verify at any time** → To check if anything's been changed

Think of it like a notary stamp that can't be forged, and each stamp references the one before it.

---

## Checking If Your Data Has Been Tampered With

### Verify a Single Block

```php
$result = Blockchain::verifyBlock($blockHash);

if ($result['valid']) {
    echo "✓ This record is authentic and untampered";
} else {
    echo "⚠️ Warning: This record may have been modified!";
    echo "Reason: " . $result['message'];
}
```

### Verify an Entire Chain for a Record

```php
$result = Blockchain::verifyChain('users', $userId);

if ($result['valid']) {
    echo "✓ All {$result['total_blocks']} records in this chain are valid";
} else {
    echo "⚠️ Chain integrity compromised!";
    print_r($result['invalid_blocks']);
}
```

### Check If Current Data Matches the Blockchain

```php
$user = User::find($userId);

$result = Blockchain::verifyData(
    'users',
    $user->id,
    $user->only('id', 'email', 'updated_at')
);

if ($result['valid']) {
    echo "✓ Database matches blockchain – all good!";
} else {
    echo "⚠️ Data mismatch detected! Someone may have modified the database directly.";
}
```

---

## Viewing History (Your Audit Trail)

Want to see every change ever made to a record?

```php
$history = Blockchain::getHistory('users', $userId);

foreach ($history as $block) {
    echo "Block #{$block->id} - {$block->created_at}\n";
    echo "Hash: {$block->block_hash}\n";
    echo "Previous: {$block->previous_hash}\n";
    echo "---\n";
}
```

This gives you a complete, verifiable history of all changes.

---

## Advanced Features (When You Need More Control)

### User-Specific Certificates (Multi-User Apps)

If you're building a multi-user system where each user needs their own cryptographic identity:

```php
public function store(Request $request)
{
    $user = User::create(['email' => $request->email]);

    // Create a block signed with the user's own private key
    $block = Blockchain::createBlock(
        'users',
        $user->id,
        $user->only('id', 'email'),
        Auth::id(),                              // Who's creating this
        $request->file('private_key'),           // User's private key
        $request->input('private_key_password')  // Key password
    );

    return response()->json(['user' => $user, 'block' => $block]);
}
```

### Using Custom Keys

```php
// Use a different set of keys for specific operations
$block = Blockchain::setPrivateKey('/path/to/custom-private.pem', 'password')
    ->setPublicKey('/path/to/custom-public.pem')
    ->createBlock('orders', $orderId, $orderData);
```

### Automatic Blockchain on Model Changes

Want to automatically create blockchain records when your models change? Add this to your model:

```php
class Order extends Model
{
    protected static function boot()
    {
        parent::boot();

        static::created(function ($order) {
            Blockchain::createBlock(
                'orders',
                $order->id,
                $order->only('id', 'total', 'status', 'created_at')
            );
        });

        static::updated(function ($order) {
            Blockchain::createBlock(
                'orders',
                $order->id,
                $order->only('id', 'total', 'status', 'updated_at')
            );
        });
    }
}
```

Now every order creation and update is automatically recorded in the blockchain. Set it and forget it!

---

## Artisan Commands (Your Blockchain Toolkit)

### Generate New Keys

```bash
php artisan blockchain:generate-keys --password=yourpassword --bits=4096
```

### Verify a Chain from the Command Line

```bash
php artisan blockchain:verify users 1
```

Output:
```
✓ Entire chain is valid
Total blocks verified: 5
```

### Health Check (Is Everything Working?)

Run this regularly to make sure your blockchain system is healthy:

```bash
php artisan blockchain:health
```

You'll get a comprehensive report covering:
- ✅ Environment checks (PHP, OpenSSL, extensions)
- 🔑 Key validation (do your keys exist and work?)
- 💾 Database health (connection, schema, indexes)
- 📊 Activity metrics (blocks created, verifications run)
- 🔍 Chain integrity (sample verification, orphaned blocks)
- 💿 Disk space monitoring

For machine-readable output (great for monitoring systems):
```bash
php artisan blockchain:health --json
```

---

## Configuration Options

Open `config/blockchain.php` to customize behavior:

```php
return [
    // The table where blockchain records are stored
    'table_name' => 'blockchain_ledgers',
    
    // Hash algorithm (sha256, sha512, etc.)
    'hash_algorithm' => 'sha256',
    
    // Where your keys are stored
    'keys_path' => storage_path('blockchain/keys'),
    
    // Auto-verify the chain after creating each block?
    // Slightly slower, but catches issues immediately
    'auto_verify' => false,
    
    // Enable Merkle root verification for hierarchical signing
    // Provides an extra layer of security
    'with_blockchain_root' => false,
    
    // Genesis hash (the starting point of all chains)
    'genesis_hash' => '00000',
];
```

---

## Making It Even Easier (Optional Trait)

Add this trait to your models for cleaner code:

```php
namespace App\Traits;

use RonaldPH\LaravelBlockchain\Facades\Blockchain;

trait HasBlockchain
{
    public function createBlockchainRecord($data = null)
    {
        $data = $data ?? $this->toArray();
        return Blockchain::createBlock($this->getTable(), $this->id, $data);
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

Now your models can do this:

```php
class Invoice extends Model
{
    use HasBlockchain;
}

// Usage is super clean
$invoice->createBlockchainRecord();
$history = $invoice->getBlockchainHistory();
$result = $invoice->verifyBlockchain();
```

---

## Security Best Practices (Please Read This!)

This package provides strong cryptographic security, but you need to use it correctly:

🔐 **NEVER commit your private keys to Git** – Add `storage/blockchain/keys/*` to your `.gitignore`

🔒 **Restrict key file permissions** – Run `chmod 700 storage/blockchain/keys` on your server

💪 **Use strong passwords** – Your private key password is the last line of defense

💾 **Back up your keys** – If you lose them, you lose the ability to verify your blockchain

🔍 **Run health checks regularly** – `php artisan blockchain:health` should be part of your monitoring

👥 **Use user-specific certificates** – In multi-user apps, give each user their own keys

📊 **Monitor for suspicious activity** – Set up alerts if verification failures occur

🔄 **Rotate keys periodically** – For high-security applications, establish a key rotation schedule

---

## Upgrading from v1.2.1 to v2.0.0

Version 2.0 adds some great new features:

```bash
# Update the package
composer update ronald-ph/laravel-blockchain

# Republish config and migrations
php artisan vendor:publish --tag=blockchain-config --force
php artisan vendor:publish --tag=blockchain-migrations --force
php artisan migrate
```

New in v2.0:
- 🎫 User-specific certificates for multi-user security
- 🏥 Comprehensive health check command
- 🔍 Enhanced chain verification and fork detection
- 📊 Better metrics and monitoring

---

## Understanding the Tech (For the Curious)

You don't need to know this to use the package, but here's what happens under the hood:

**When you create a block:**
1. Your data gets hashed (turned into a unique fingerprint)
2. That hash gets combined with the previous block's hash (creating the chain)
3. Everything gets signed with your private key (proof of authenticity)
4. The block gets stored with all this cryptographic proof

**When you verify:**
1. The system recalculates the hash from the stored data
2. It checks if the hash matches what was originally recorded
3. It verifies the digital signature using your public key
4. It checks that each block properly links to the one before it

If any of this fails, you know something's been tampered with!

---

## Testing

```bash
composer test
```

---

## Contributing & Support

Found a bug? Have a feature request? Want to contribute?

📦 [GitHub Repository](https://github.com/ronald-ph/laravel-blockchain)  
🐛 [Issue Tracker](https://github.com/ronald-ph/laravel-blockchain/issues)

---

## License

Open-source and free to use under the [MIT License](https://github.com/Ronald-PH/laravel-blockchain/?tab=MIT-1-ov-file).

---

## Credits

Built with ☕ by **Ronald PH**

If this package saves you time or makes your app more secure, consider giving it a ⭐ on GitHub!

---

**Questions?** Don't hesitate to open an issue. We're here to help make your data more secure.
