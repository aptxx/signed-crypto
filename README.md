# signed-crypto

A Rust library for encrypted payloads with built-in integrity verification.

## Overview

`signed-crypto` provides a secure way to encrypt and transmit arbitrary data payloads. Each encrypted package includes:

- **Confidentiality** via AES-256 CTR encryption
- **Integrity** via HMAC-SHA256 signatures
- **Metadata** via embedded timestamps and server identifiers
- **Transparency** via URL-safe Base64 encoding

## Installation

```toml
[dependencies]
signed-crypto = "0.1"
```

## Quick Start

```rust
use signed_crypto::{Crypto, Keys};

let keys = Keys::new(&enc_key, &integrity_key)?;
let crypto = Crypto::new(keys);

// Encrypt
let mut pkg = crypto.init_plain_data(payload.len(), None)?;
crypto.set_payload(&mut pkg, payload)?;
let encrypted = crypto.encrypt(&pkg)?;
let encoded = crypto.encode(&encrypted);

// Decrypt
let decoded = crypto.decode(&encoded)?;
let decrypted = crypto.decrypt(&decoded)?;
```

## Package Format

```
┌────────────────────┬─────────────────────┬────────────┐
│ IV (16 bytes)      │ Encrypted Payload   │ HMAC (4B)  │
│ timestamp + srv_id │ AES-256/CTR         │            │
└────────────────────┴─────────────────────┴────────────┘
```

Overhead: 20 bytes per package.

## Features

- **Authenticated Encryption** — AES-256 + HMAC-SHA256
- **Wire-Safe** — URL-safe Base64 encoding
- **Metadata** — Timestamp and server ID in IV
- **Zero-Copy** — Efficient payload access

## Security Notes

- Use unique IVs for each encryption (automatic with `init_plain_data`)
- Rotate keys periodically
- 4-byte HMAC is suitable for integrity, not adversarial environments

## Acknowledgments

Inspired by Google's DoubleClick crypto implementation:
https://github.com/google/openrtb-doubleclick/blob/master/doubleclick-core/src/main/java/com/google/doubleclick/crypto/DoubleClickCrypto.java

## License

Copyright 2026, Kehan Pan, All rights reserved.
