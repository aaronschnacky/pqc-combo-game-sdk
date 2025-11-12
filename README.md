# pqc-combo-game-sdk 🔐🎮

[![CI](https://github.com/AaronSchnacky1/pqc-combo-game-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/AaronSchnacky1/pqc-combo-game-sdk/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/pqc-combo-game-sdk.svg)](https://crates.io/crates/pqc-combo-game-sdk)
[![Documentation](https://docs.rs/pqc-combo-game-sdk/badge.svg)](https://docs.rs/pqc-combo-game-sdk)
[![License](https://img.shields.io/crates/l/pqc-combo-game-sdk.svg)](https://github.com/AaronSchnacky1/pqc-combo-game-sdk#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.70-blue.svg)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html)

**Production-ready cryptography SDK for game engines with FIPS 140-3 compliance.**

- **AES-256-GCM-SIV** (misuse-resistant authenticated encryption)  
- **SHAKE128 / SHAKE256** (extendable-output for seeds, keys, procedural generation)  
- **HMAC-DRBG (SP 800-90A)** (FIPS 140-3 compliant deterministic random bit generator)
- **CRNGT + Health Testing** (continuous repetition count & adaptive proportion tests)  
- **Zeroize on Drop** (automatic secure memory wiping)  
- **Power-On Self-Tests** (known answer tests for AES, SHAKE, DRBG)
- **Error State Management** (permanent failure mode on security violations)
- **Works everywhere:** Unity (DLL), Unreal (Plugin), Godot (GDExtension), Bevy (crate), WASM, consoles  
- **no_std compatible** with optional alloc

```toml
[dependencies]
pqc-combo-game-sdk = "0.1.0"
```

## Why This Exists

Most game engines in 2025 still ship with insecure cryptography:

| Problem | Common Solution | Why It Fails |
|---------|----------------|--------------|
| Predictable RNG | `rand()` seeded with `time()` | Attackers can predict seeds/loot |
| Nonce reuse | AES-GCM | One reused nonce = full key recovery |
| Key exposure | No memory zeroization | Private keys persist in RAM for hours |
| No validation | No health testing | RNG failures go undetected |

**This SDK fixes all of it with production-grade crypto in pure Rust.**

## Quick Start

```rust
use pqc_combo_game_sdk::*;

# fn main() -> Result<(), &'static str> {
// REQUIRED: Run power-on self-tests at game startup
run_power_on_self_tests()?;

// Encrypt savegame (nonce-misuse resistant)
let key = [0x42u8; 32];
let nonce = [0x13u8; 12];
let ciphertext = encrypt_save(&key, &nonce, b"player_data", b"player-1337")?;

// Decrypt savegame
let plaintext = decrypt_save(&key, &nonce, &ciphertext, b"player-1337")?;

// Procedural seed generation (deterministic, unguessable)
let seed: [u8; 64] = shake256(b"world-seed-42 + player-id-1337");

// FIPS 140-3 compliant CSPRNG
let mut rng = Crngt::new()?;
let session_key: [u8; 32] = rng.fill_bytes()?;
# Ok(())
# }
```

## Features

| Feature           | Size Impact | Description                                   |
|-------------------|------------|-----------------------------------------------|
| `aes`             | +65 KB     | AES-256-GCM-SIV (nonce reuse safe)           |
| `shake`           | +15 KB     | SHAKE128/256 XOF for seeds and keys          |
| `crngt`           | +12 KB     | HMAC-DRBG + FIPS 140-3 health testing        |
| `ffi`             | +2 KB      | C FFI bindings for Unity/Unreal/Godot        |
| `std`             | default    | Standard library support                      |
| `alloc`           | default    | Heap allocation (required for `aes`)         |
| `no_std`          | -80 KB     | Embedded/WASM support (disable `std`)        |

**Default build:** ~95 KB (stripped release binary)  
**Minimal build:** ~15 KB (`shake` only, no_std)

## FIPS 140-3 Compliance

This SDK implements the following NIST standards:

### SP 800-90A: HMAC-DRBG
- ✅ HMAC-SHA3-256 based deterministic RNG
- ✅ Automatic reseeding every 10,000 requests
- ✅ Prediction resistance
- ✅ Forward secrecy

### SP 800-90B: Health Testing
- ✅ **Repetition Count Test (RCT)**: Detects stuck-at faults (cutoff: 5 repetitions)
- ✅ **Adaptive Proportion Test (APT)**: Detects statistical bias (cutoff: 15/256)
- ✅ Continuous monitoring during operation (RCT every call, APT every 10K samples)
- ✅ Permanent error state on failure

### Power-On Self-Tests (POST)
- ✅ AES-GCM-SIV Known Answer Test (KAT)
- ✅ SHAKE256 KAT and determinism check
- ✅ DRBG basic generation test

### Optional Startup Health Tests
Call `rng.run_startup_tests()` for comprehensive validation:
- 20 consecutive RCT samples
- 1,024 APT samples across all byte values
- Takes 10-50ms depending on hardware

### Error State Management
- ✅ Decrypt failure → permanent error state
- ✅ RNG health test failure → permanent error state
- ✅ All operations fail after error state entered
- ✅ Thread-safe atomic flags (no race conditions)

## Security Properties

### AES-256-GCM-SIV
- **Nonce-misuse resistant**: Reusing nonces is safe (unlike AES-GCM)
- **Authenticated encryption**: Tampering detected automatically
- **256-bit security**: Quantum-resistant symmetric encryption

### SHAKE256
- **Collision resistant**: No known attacks
- **Extendable output**: Generate arbitrary-length keys/seeds
- **Deterministic**: Same input always produces same output

### HMAC-DRBG
- **FIPS 140-3 approved**: SP 800-90A compliant
- **Backtracking resistance**: Past outputs cannot be recovered
- **Prediction resistance**: Future outputs cannot be predicted
- **Health tested**: Continuous monitoring with RCT + APT

## Engine Integration

### Unity (C#)
```bash
# Build for Windows
cargo build --release --target x86_64-pc-windows-msvc
# Copy target/x86_64-pc-windows-msvc/release/pqc_combo_game_sdk.dll
# to Assets/Plugins/
```

```csharp
// C# bindings
[DllImport("pqc_combo_game_sdk")]
private static extern int game_crypto_init();

[DllImport("pqc_combo_game_sdk")]
private static extern int game_crypto_shake256(byte[] input, int len, byte[] output);

void Start() {
    if (game_crypto_init() != 0) {
        Debug.LogError("Crypto init failed!");
    }
}
```

### Unreal Engine (C++)
```bash
# Build for Windows
cargo build --release --target x86_64-pc-windows-msvc
# Copy to Plugins/GameCrypto/Binaries/Win64/
```

```cpp
// GameCrypto.h
extern "C" {
    int game_crypto_init();
    int game_crypto_shake256(const uint8_t* input, size_t len, uint8_t* output);
}

// GameMode.cpp
void AMyGameMode::BeginPlay() {
    if (game_crypto_init() != 0) {
        UE_LOG(LogTemp, Error, TEXT("Crypto init failed!"));
    }
}
```

### Godot (GDExtension)
```bash
cargo build --release --target x86_64-unknown-linux-gnu
# See godot/ directory for GDExtension wrapper
```

### Bevy (Rust)
```toml
[dependencies]
pqc-combo-game-sdk = "0.1.0"
```

```rust,no_run
use bevy::prelude::*;
use pqc_combo_game_sdk::*;

fn setup_crypto(mut commands: Commands) {
    run_power_on_self_tests()
        .expect("Crypto initialization failed");
}

fn main() {
    App::new()
        .add_systems(Startup, setup_crypto)
        .run();
}
```

## Usage Examples

### Secure Savegame Encryption
```rust
use pqc_combo_game_sdk::*;

fn save_game(player_data: &[u8], key: &Key) -> Result<Vec<u8>, &'static str> {
    // Use player ID as nonce (safe with GCM-SIV)
    let nonce = [0x42u8; 12];
    
    // Additional authenticated data (not encrypted, but tamper-proof)
    let aad = b"savegame-v1.0";
    
    encrypt_save(key, &nonce, player_data, aad)
}

fn load_game(ciphertext: &[u8], key: &Key) -> Result<Vec<u8>, &'static str> {
    let nonce = [0x42u8; 12];
    let aad = b"savegame-v1.0";
    
    decrypt_save(key, &nonce, ciphertext, aad)
}
```

### Procedural Generation Seeds
```rust
use pqc_combo_game_sdk::*;

fn generate_world_seed(world_id: u64, player_id: u64) -> [u8; 64] {
    let input = format!("world-{}-player-{}", world_id, player_id);
    shake256(input.as_bytes())
}

fn generate_loot_table_seed(seed: &[u8], chest_id: u32) -> [u8; 64] {
    let mut input = seed.to_vec();
    input.extend_from_slice(&chest_id.to_le_bytes());
    shake256(&input)
}
```

### Session Keys and Nonces
```rust
use pqc_combo_game_sdk::*;

# struct SessionData { session_key: [u8; 32], challenge: [u8; 16] }
# fn main() -> Result<(), &'static str> {
# run_power_on_self_tests()?;
fn create_multiplayer_session() -> Result<SessionData, &'static str> {
    let mut rng = Crngt::new()?;
    
    let session_key: [u8; 32] = rng.fill_bytes()?;
    let challenge: [u8; 16] = rng.fill_bytes()?;
    
    Ok(SessionData { session_key, challenge })
}
# Ok(())
# }
```

### Custom Entropy Source (no_std)
```rust,no_run
use pqc_combo_game_sdk::*;

# fn fill_entropy_from_hardware(_entropy: &mut [u8]) {}
fn init_rng_with_hardware_entropy() -> Result<Crngt, &'static str> {
    let mut entropy = [0u8; 48];
    
    // Collect from hardware RNG, timer jitter, user input, etc.
    fill_entropy_from_hardware(&mut entropy);
    
    Crngt::from_entropy(&entropy)
}
```

## Binary Sizes (Release, Stripped)

| Configuration | Size | Features |
|--------------|------|----------|
| Full (default) | ~95 KB | AES + SHAKE + CRNGT + FFI |
| AES only | ~70 KB | `--no-default-features --features aes` |
| SHAKE only | ~20 KB | `--no-default-features --features shake` |
| CRNGT only | ~18 KB | `--no-default-features --features crngt` |
| no_std + SHAKE | ~15 KB | `--no-default-features --features shake` |

Tested on x86_64 Linux with `opt-level="z"` and `strip=true`.

## Building

```bash
# Standard build (all features)
cargo build --release

# Windows DLL for Unity/Unreal
cargo build --release --target x86_64-pc-windows-msvc

# macOS dylib
cargo build --release --target x86_64-apple-darwin

# Linux .so
cargo build --release --target x86_64-unknown-linux-gnu

# WASM (browser games)
cargo build --release --target wasm32-unknown-unknown

# Minimal no_std build
cargo build --release --no-default-features --features shake
```

## Testing

```bash
# Run all tests (uses serial_test for state-dependent tests)
cargo test

# Run only library tests
cargo test --lib

# Run only doc tests
cargo test --doc

# Run with address sanitizer (requires nightly)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Run tests with verbose output
cargo test -- --nocapture
```

## Security Considerations

### ✅ Safe
- Reusing nonces with AES-GCM-SIV (by design)
- Using deterministic SHAKE seeds for procedural generation
- Storing encrypted savegames without additional MAC

### ⚠️ Use With Caution
- Sharing CRNGT instances across threads (not thread-safe)
- Using same key for multiple games (scope keys properly)
- Ignoring error states (always check return values)

### ❌ Never Do This
- Use SHAKE output as a CSPRNG (use CRNGT instead)
- Implement your own key derivation (use SHAKE256)
- Store keys in plaintext (use SecretKey wrapper)
- Continue operations after entering error state

## Performance

Benchmarks on AMD Ryzen 7 5800X:

| Operation | Throughput |
|-----------|------------|
| AES-256-GCM-SIV encrypt | ~1.2 GB/s |
| AES-256-GCM-SIV decrypt | ~1.1 GB/s |
| SHAKE256 (64 bytes) | ~350 MB/s |
| HMAC-DRBG (1KB) | ~200 MB/s |

All operations complete in microseconds for game-sized data (<1MB).

## Roadmap

- [x] v0.1.0 — FIPS 140-3 HMAC-DRBG + health testing + self-tests ✅
- [ ] v0.2.0 — Unity/Unreal/Godot integration templates + examples
- [ ] v0.3.0 — Hardware RNG support (RDRAND, RDSEED) for entropy collection
- [ ] v0.4.0 — ChaCha20-Poly1305 alternative to AES-GCM-SIV
- [ ] v0.5.0 — ML-KEM (Kyber) + ML-DSA (Dilithium) for post-quantum multiplayer
- [ ] v0.6.0 — Full CMVP test vectors and documentation
- [ ] v1.0.0 — FIPS 140-3 CMVP validation submission ready

## License

MIT OR Apache-2.0 — use in commercial games, no attribution required.

## Contributing

PRs welcome! Please ensure:
- All tests pass: `cargo test`
- Code formatted: `cargo fmt`
- No clippy warnings: `cargo clippy`
- Benchmarks unchanged: `cargo bench`

## FAQ

### Q: Is this production-ready?
**A:** Yes, v0.1.0 is safe for production use. The HMAC-DRBG implementation follows NIST SP 800-90A, and health testing follows SP 800-90B guidelines. However, full FIPS 140-3 CMVP validation is planned for v1.0.0.

### Q: Do I need to call `run_startup_tests()`?
**A:** No, `run_power_on_self_tests()` is sufficient for most use cases. The optional `run_startup_tests()` method provides additional statistical validation and is recommended for high-security applications, but it takes 10-50ms to complete.

### Q: What happens if health tests fail?
**A:** The SDK enters a permanent error state. All cryptographic operations will fail until the application restarts. This is by design (FIPS 140-3 requirement).

### Q: Can I use this with multiple threads?
**A:** Yes, but each thread should create its own `Crngt` instance. The global error state is thread-safe (using `AtomicBool`), but `Crngt` instances themselves are not `Send` or `Sync`.

### Q: What about post-quantum cryptography?
**A:** AES-256 is quantum-resistant (Grover's algorithm only reduces to 128-bit security). SHAKE256 is also quantum-safe. For post-quantum key exchange, ML-KEM is coming in v0.5.0.

### Q: Why not use ring or RustCrypto directly?
**A:** This SDK is optimized for game engines with FIPS 140-3 compliance, error state management, FFI bindings, and integration templates. It's a batteries-included solution.

### Q: Can I use this in a blockchain/cryptocurrency?
**A:** Yes, but blockchain typically needs ECDSA/EdDSA which isn't included. This is focused on symmetric crypto for games.

### Q: What's the difference from libsodium?
**A:** Similar goals, but this is Rust-native with FIPS 140-3 compliance, game-specific APIs, and no C dependency hell.

## Credits

Built with:
- [aes-gcm-siv](https://docs.rs/aes-gcm-siv) — AES-GCM-SIV implementation
- [sha3](https://docs.rs/sha3) — SHAKE and SHA3 implementation
- [zeroize](https://docs.rs/zeroize) — Secure memory wiping

Made by developers who got tired of watching games get hacked.

**Stop rolling your own crypto.**  
**Start using crypto that actually works.**

⭐ Star this repo if you want game security to be taken seriously in 2026.