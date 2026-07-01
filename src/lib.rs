// Copyright 2026, Kehan Pan, All rights reserved.
//
// Cryptographic scheme inspired by:
// https://github.com/google/openrtb-doubleclick/blob/master/doubleclick-core/src/main/java/com/google/doubleclick/crypto/DoubleClickCrypto.java

//! # signed-crypto
//!
//! A Rust library for encrypted payloads with built-in integrity verification.
//!
//! ## Package Format
//!
//! Encrypted payloads follow this structure:
//!
//! ```text
//! initVector:16 || E(payload:?) || I(signature:4)
//! ```
//!
//! where:
//! - `initVector` = `timestamp:8 || serverId:8`
//! - `E(payload)` = AES-256/CTR64 encryption with encryption key
//! - `I(signature)` = First 4 bytes of HMAC-SHA256(integrityKey, payload || initVector)
//!
//! ## Example
//!
//! ```rust
//! use signed_crypto::{Crypto, Keys};
//!
//! // WARNING: Never use all-zero keys in production!
//! // Generate secure random keys using a cryptographic RNG.
//! let keys = Keys::new(&[0u8; 32], &[0u8; 32]).unwrap();
//! let crypto = Crypto::new(keys);
//!
//! // Encrypt → URL-safe Base64 string
//! let encoded = crypto.package(b"Hello, world!", None).unwrap();
//!
//! // Decrypt → original payload
//! let payload = crypto.unpackage(&encoded).unwrap();
//! assert_eq!(payload, b"Hello, world!");
//! ```

use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use std::io::Write;
use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

const UNIX_EPOCH: OffsetDateTime = time::OffsetDateTime::UNIX_EPOCH;

/// Holds the encryption and integrity keys.
///
/// Both keys must be exactly 32 bytes (256 bits).
///
/// # Fields
///
/// * `encryption_key` - AES-256 encryption key
/// * `integrity_key` - HMAC-SHA256 integrity key
#[derive(Clone, Debug)]
pub struct Keys {
    /// AES-256 encryption key (32 bytes)
    pub encryption_key: [u8; 32],
    /// HMAC-SHA256 integrity key (32 bytes)
    pub integrity_key: [u8; 32],
}

impl Keys {
    /// Creates a new `Keys` instance from raw byte slices.
    ///
    /// Both keys must be exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if either key is not 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::Keys;
    ///
    /// let enc_key = [0u8; 32];
    /// let int_key = [0u8; 32];
    /// let keys = Keys::new(&enc_key, &int_key).unwrap();
    /// ```
    pub fn new(encryption_key: &[u8], integrity_key: &[u8]) -> Result<Self, CryptoError> {
        let encryption_key: [u8; 32] = encryption_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let integrity_key: [u8; 32] = integrity_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;

        Ok(Self {
            encryption_key,
            integrity_key,
        })
    }
}

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key is not exactly 32 bytes.
    #[error("invalid key")]
    InvalidKey,
    /// HMAC signature verification failed.
    #[error("invalid signature")]
    InvalidSign,
    /// Initialization vector is invalid.
    #[error("invalid init vector")]
    InvalidInitVector,
    /// Data is too short to be a valid package.
    #[error("data too short")]
    DataTooShort,
    /// Payload size does not match expected size.
    #[error("payload size mismatch")]
    PayloadSizeMismatch,
    /// Base64 decoding failed.
    #[error("decode error: {0}")]
    DecodeError(#[from] base64::DecodeError),
    /// Writing to the output stream failed.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Main cryptographic operations instance.
///
/// Holds the keys and provides methods for encryption, decryption,
/// and metadata extraction.
///
/// # Example
///
/// ```rust
/// use signed_crypto::{Crypto, Keys};
///
/// let keys = Keys::new(&[0u8; 32], &[0u8; 32]).unwrap();
/// let crypto = Crypto::new(keys);
/// ```
pub struct Crypto {
    /// The encryption and integrity keys.
    pub keys: Keys,
}

impl Crypto {
    /// Creates a new `Crypto` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let keys = Keys::new(&[0u8; 32], &[0u8; 32]).unwrap();
    /// let crypto = Crypto::new(keys);
    /// ```
    pub fn new(keys: Keys) -> Self {
        Self { keys }
    }

    /// Offset of the initialization vector in a package.
    pub const IV_BASE: usize = 0;
    /// Size of the initialization vector in bytes.
    pub const IV_SIZE: usize = 16;
    /// Offset of the timestamp within the IV.
    pub const IV_TIME_OFFSET: usize = 0;
    /// Size of the timestamp in bytes.
    pub const IV_TIME_SIZE: usize = 8;
    /// Offset of the server ID within the IV.
    pub const IV_SERVER_ID_OFFSET: usize = 8;
    /// Size of the server ID in bytes.
    pub const IV_SERVER_ID_SIZE: usize = 8;
    /// Size of the HMAC signature in bytes.
    pub const SIGNATURE_SIZE: usize = 4;
    /// Offset where the payload begins.
    pub const PAYLOAD_BASE: usize = Crypto::IV_BASE + Crypto::IV_SIZE;
    /// Total overhead size (IV + signature) in bytes.
    pub const OVERHEAD_SIZE: usize = Crypto::IV_SIZE + Crypto::SIGNATURE_SIZE;

    /// Decodes a URL-safe Base64 encoded string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let encoded = "SGVsbG8=";
    /// let decoded = crypto.decode(encoded).unwrap();
    /// ```
    #[inline]
    pub fn decode<T>(&self, data: T) -> Result<Vec<u8>, CryptoError>
    where
        T: AsRef<[u8]>,
    {
        URL_SAFE
            .decode(data)
            .map(|v| v.to_vec())
            .map_err(|e| e.into())
    }

    /// Encodes data as a URL-safe Base64 string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let data = b"Hello";
    /// let encoded = crypto.encode(data);
    /// ```
    #[inline]
    pub fn encode<T>(&self, data: T) -> String
    where
        T: AsRef<[u8]>,
    {
        URL_SAFE.encode(data)
    }

    /// Decrypts a package and verifies the HMAC signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSign`] if signature verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// let encrypted = crypto.encrypt(&pkg).unwrap();
    /// let decrypted = crypto.decrypt(&encrypted).unwrap();
    /// ```
    #[inline]
    pub fn decrypt(&self, cipher_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if cipher_data.len() < Self::OVERHEAD_SIZE {
            return Err(CryptoError::DataTooShort);
        }

        let mut data = cipher_data.to_vec();
        let data_size = data.len();

        self.xor_payload(&mut data)?;

        let confirmation_signature = self.hmac_signature(&data)?;
        let integrity_signature = self.read_i32(&data, data_size - Self::SIGNATURE_SIZE);
        self.write_i32(
            &mut data,
            data_size - Self::SIGNATURE_SIZE,
            confirmation_signature,
        );

        if confirmation_signature != integrity_signature {
            return Err(CryptoError::InvalidSign);
        }

        Ok(data)
    }

    /// Encrypts a package in-place.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// let encrypted = crypto.encrypt(&pkg).unwrap();
    /// ```
    #[inline]
    pub fn encrypt(&self, plain_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plain_data.len() < Self::OVERHEAD_SIZE {
            return Err(CryptoError::DataTooShort);
        }

        let mut data = plain_data.to_vec();
        let data_size = data.len();
        let signature = self.hmac_signature(&data)?;
        self.write_i32(&mut data, data_size - Self::SIGNATURE_SIZE, signature);

        self.xor_payload(&mut data)?;

        Ok(data)
    }

    /// Packages a payload into a URL-safe Base64 encoded encrypted string.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to encrypt
    /// * `iv` - Optional custom initialization vector; a random IV with the
    ///   current timestamp is generated when `None`
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let encoded = crypto.package(b"Hello, world!", None).unwrap();
    /// ```
    #[inline]
    pub fn package<T>(
        &self,
        payload: T,
        iv: Option<&[u8]>,
    ) -> Result<String, CryptoError>
    where
        T: AsRef<[u8]>,
    {
        let mut out = Vec::new();
        self.package_to(payload, iv, &mut out)?;
        // `package_to` writes Base64 output, which is always valid ASCII/UTF-8.
        Ok(String::from_utf8(out).expect("base64 output is valid UTF-8"))
    }

    /// Unpackages and decrypts a URL-safe Base64 encoded encrypted string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSign`] if signature verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let encoded = crypto.package(b"Hello, world!", None).unwrap();
    /// let payload = crypto.unpackage(&encoded).unwrap();
    /// assert_eq!(payload, b"Hello, world!");
    /// ```
    #[inline]
    pub fn unpackage<T>(&self, data: T) -> Result<Vec<u8>, CryptoError>
    where
        T: AsRef<[u8]>,
    {
        let mut out = Vec::new();
        self.unpackage_to(data, &mut out)?;
        Ok(out)
    }

    /// Packages a payload and writes the URL-safe Base64 encoded encrypted
    /// result into the provided writer.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to encrypt
    /// * `iv` - Optional custom initialization vector; a random IV with the
    ///   current timestamp is generated when `None`
    /// * `out` - Any writer that receives the Base64-encoded encrypted package
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut buf = Vec::new();
    /// crypto.package_to(b"Hello, world!", None, &mut buf).unwrap();
    /// ```
    #[inline]
    pub fn package_to<T, W>(
        &self,
        payload: T,
        iv: Option<&[u8]>,
        out: &mut W,
    ) -> Result<(), CryptoError>
    where
        T: AsRef<[u8]>,
        W: Write,
    {
        let payload = payload.as_ref();
        let mut pkg = self.init_plain_data(payload.len(), iv)?;
        self.set_payload(&mut pkg, payload)?;
        let encrypted = self.encrypt(&pkg)?;
        out.write_all(URL_SAFE.encode(&encrypted).as_bytes())?;
        Ok(())
    }

    /// Unpackages and decrypts a URL-safe Base64 encoded string, writing the
    /// decrypted payload into the provided writer.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSign`] if signature verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let encoded = crypto.package(b"Hello, world!", None).unwrap();
    /// let mut buf = Vec::new();
    /// crypto.unpackage_to(&encoded, &mut buf).unwrap();
    /// assert_eq!(buf, b"Hello, world!");
    /// ```
    #[inline]
    pub fn unpackage_to<T, W>(
        &self,
        data: T,
        out: &mut W,
    ) -> Result<(), CryptoError>
    where
        T: AsRef<[u8]>,
        W: Write,
    {
        let decoded = self.decode(data)?;
        let decrypted = self.decrypt(&decoded)?;
        let payload = self.payload(&decrypted).ok_or(CryptoError::DataTooShort)?;
        out.write_all(payload)?;
        Ok(())
    }

    /// Creates a custom initialization vector.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp to embed
    /// * `server_id` - The server ID to embed
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    /// use time::OffsetDateTime;
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let iv = crypto.create_init_vector(OffsetDateTime::now_utc(), 12345);
    /// ```
    #[inline]
    pub fn create_init_vector(&self, timestamp: OffsetDateTime, server_id: i64) -> Vec<u8> {
        let timestamp = (timestamp.unix_timestamp_nanos() / 1_000) as i64; // microseconds
        let mut iv = vec![0; Self::IV_SIZE];
        self.write_i64(&mut iv, Self::IV_TIME_OFFSET, timestamp);
        self.write_i64(&mut iv, Self::IV_SERVER_ID_OFFSET, server_id);
        iv
    }

    /// Extracts the timestamp from a package's initialization vector.
    ///
    /// Returns `None` if the data is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    /// use time::OffsetDateTime;
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// let encrypted = crypto.encrypt(&pkg).unwrap();
    /// let ts = crypto.timestamp(&encrypted).unwrap();
    /// ```
    #[inline]
    pub fn timestamp(&self, data: &[u8]) -> Option<OffsetDateTime> {
        if data.len() < Self::IV_SIZE {
            return None;
        }
        let ts = self.read_i64(data, Self::IV_BASE + Self::IV_TIME_OFFSET);
        Some(
            UNIX_EPOCH
                .checked_add(Duration::microseconds(ts))
                .unwrap_or(UNIX_EPOCH),
        )
    }

    /// Extracts the server ID from a package's initialization vector.
    ///
    /// Returns `None` if the data is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// let encrypted = crypto.encrypt(&pkg).unwrap();
    /// let server_id = crypto.server_id(&encrypted).unwrap();
    /// ```
    #[inline]
    pub fn server_id(&self, data: &[u8]) -> Option<i64> {
        if data.len() < Self::IV_SIZE {
            return None;
        }
        Some(self.read_i64(data, Self::IV_BASE + Self::IV_SERVER_ID_OFFSET))
    }

    /// Extracts the payload from a package without decryption.
    ///
    /// Returns `None` if the data is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// let payload = crypto.payload(&pkg).unwrap();
    /// assert_eq!(payload, b"Hello");
    /// ```
    #[inline]
    pub fn payload<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() < Self::OVERHEAD_SIZE {
            return None;
        }
        Some(&data[Self::PAYLOAD_BASE..data.len() - Self::SIGNATURE_SIZE])
    }

    /// Initializes a plain data package buffer.
    ///
    /// If `iv` is `None`, generates a random IV with current timestamp.
    ///
    /// # Arguments
    ///
    /// * `payload_size` - Size of the payload in bytes
    /// * `iv` - Optional custom initialization vector
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let pkg = crypto.init_plain_data(10, None).unwrap();
    /// ```
    #[inline]
    pub fn init_plain_data(
        &self,
        payload_size: usize,
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut plain_data = vec![0; Self::OVERHEAD_SIZE + payload_size];
        if let Some(iv) = iv {
            plain_data[Self::IV_BASE..Self::IV_BASE + Self::IV_SIZE].copy_from_slice(iv);
        } else {
            let now = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000) as i64;
            self.write_i64(&mut plain_data, Self::IV_TIME_OFFSET, now);
            self.write_i64(
                &mut plain_data,
                Self::IV_SERVER_ID_OFFSET,
                rand::random::<i64>(),
            );
        }

        Ok(plain_data)
    }

    /// Sets the payload in a plain data package buffer.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::PayloadSizeMismatch`] if the payload size
    /// does not match the expected size.
    ///
    /// # Example
    ///
    /// ```rust
    /// use signed_crypto::{Crypto, Keys};
    ///
    /// let crypto = Crypto::new(Keys::new(&[0u8; 32], &[0u8; 32]).unwrap());
    /// let mut pkg = crypto.init_plain_data(5, None).unwrap();
    /// crypto.set_payload(&mut pkg, b"Hello").unwrap();
    /// ```
    #[inline]
    pub fn set_payload(&self, plain_data: &mut [u8], payload: &[u8]) -> Result<(), CryptoError> {
        if payload.len() != plain_data.len() - Self::OVERHEAD_SIZE {
            return Err(CryptoError::PayloadSizeMismatch);
        }
        plain_data[Self::PAYLOAD_BASE..Self::PAYLOAD_BASE + payload.len()].copy_from_slice(payload);
        Ok(())
    }

    #[inline]
    fn read_i32(&self, data: &[u8], offset: usize) -> i32 {
        BigEndian::read_i32(&data[offset..offset + 4])
    }

    #[inline]
    fn read_i64(&self, data: &[u8], offset: usize) -> i64 {
        BigEndian::read_i64(&data[offset..offset + 8])
    }

    #[inline]
    fn write_i32(&self, data: &mut [u8], offset: usize, value: i32) {
        BigEndian::write_i32(&mut data[offset..offset + 4], value);
    }

    #[inline]
    fn write_i64(&self, data: &mut [u8], offset: usize, value: i64) {
        BigEndian::write_i64(&mut data[offset..offset + 8], value);
    }

    #[inline]
    fn xor_payload(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        let iv: &[u8; 16] = &data[Self::IV_BASE..Self::IV_BASE + Self::IV_SIZE]
            .try_into()
            .map_err(|_| CryptoError::InvalidInitVector)?;

        let mut cipher = Aes256Ctr64BE::new(&self.keys.encryption_key.into(), iv.into());
        let data_size = data.len();
        cipher.apply_keystream(&mut data[Self::PAYLOAD_BASE..data_size - Self::SIGNATURE_SIZE]);

        Ok(())
    }

    #[inline]
    fn hmac_signature(&self, data: &[u8]) -> Result<i32, CryptoError> {
        let mut mac = HmacSha256::new_from_slice(&self.keys.integrity_key)
            .map_err(|_| CryptoError::InvalidKey)?;

        mac.update(&data[Self::PAYLOAD_BASE..data.len() - Self::SIGNATURE_SIZE]);
        mac.update(&data[Self::IV_BASE..Self::IV_BASE + Self::IV_SIZE]);

        let b = mac.finalize().into_bytes();

        Ok(self.read_i32(&b, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    static TEST_ENCRYPTION_KEY: &str = "sIxwz7yw62yrfoLGt12lIHKuYrK/S5kLuApI2BQe7Ac=";
    static TEST_INTEGRITY_KEY: &str = "v3fsVcMBMMHYzRhi7SpM0sdqwzvAxM6KPTu9OtVod5I=";

    fn create_keys() -> Keys {
        Keys::new(
            &BASE64_STANDARD.decode(TEST_ENCRYPTION_KEY).unwrap(),
            &BASE64_STANDARD.decode(TEST_INTEGRITY_KEY).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_decode() {
        let crypto = Crypto::new(create_keys());
        let encoded = "aGVsbG8sIHdvcmxk";
        let decoded = crypto.decode(encoded).unwrap();
        assert_eq!(decoded, b"hello, world");
    }

    #[test]
    fn test_encode() {
        let crypto = Crypto::new(create_keys());
        let data = b"hello, world";
        let encoded = crypto.encode(data);
        assert_eq!(encoded, "aGVsbG8sIHdvcmxk");
    }

    #[test]
    fn test_decrypt() {
        let crypto = Crypto::new(create_keys());
        let timestamp = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1);
        let iv = crypto.create_init_vector(timestamp, 123456789);
        let payload = "https://example.com".as_bytes();

        let mut plain_data = crypto.init_plain_data(payload.len(), Some(&iv)).unwrap();
        crypto.set_payload(&mut plain_data, payload).unwrap();
        let encrypted_data = crypto.encrypt(&plain_data).unwrap();

        assert_eq!(crypto.timestamp(&iv), Some(timestamp));
        assert_eq!(crypto.server_id(&iv), Some(123456789));
        assert_eq!(
            crypto.payload(&encrypted_data).unwrap().len(),
            payload.len()
        );
        assert_ne!(crypto.payload(&encrypted_data), Some(payload));

        let decrypted_data = crypto.decrypt(&encrypted_data).unwrap();
        assert_eq!(crypto.timestamp(&decrypted_data), Some(timestamp));
        assert_eq!(crypto.server_id(&decrypted_data), Some(123456789));
        assert_eq!(crypto.payload(&decrypted_data), Some(payload));

        let mut encrypted_data_invalid_sign = encrypted_data.clone();
        crypto.write_i32(
            &mut encrypted_data_invalid_sign,
            encrypted_data.len() - Crypto::SIGNATURE_SIZE,
            123456789,
        );
        assert!(matches!(
            crypto.decrypt(&encrypted_data_invalid_sign),
            Err(CryptoError::InvalidSign)
        ));
        assert_ne!(crypto.payload(&encrypted_data_invalid_sign), Some(payload))
    }

    #[test]
    fn test_create_init_vector() {
        let crypto = Crypto::new(create_keys());
        let timestamp = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1);
        let iv = crypto.create_init_vector(timestamp, 123456789);
        assert_eq!(iv.len(), Crypto::IV_SIZE);
        assert_eq!(crypto.read_i64(&iv, Crypto::IV_TIME_OFFSET), 1_000_000);
        assert_eq!(crypto.read_i64(&iv, Crypto::IV_SERVER_ID_OFFSET), 123456789);
        assert_eq!(crypto.timestamp(&iv), Some(timestamp));
        assert_eq!(crypto.server_id(&iv), Some(123456789));
    }

    #[test]
    fn test_init_plain_data() {
        let crypto = Crypto::new(create_keys());
        let payload = "https://example.com".as_bytes();

        let mut plain_data = crypto.init_plain_data(payload.len(), None).unwrap();
        crypto.set_payload(&mut plain_data, payload).unwrap();

        assert_eq!(plain_data.len(), Crypto::OVERHEAD_SIZE + payload.len());
        assert_eq!(crypto.payload(&plain_data), Some(payload));
    }

    #[test]
    fn test_init_plain_data_empty_payload() {
        let crypto = Crypto::new(create_keys());
        let payload = "".as_bytes();

        let mut plain_data = crypto.init_plain_data(0, None).unwrap();
        crypto.set_payload(&mut plain_data, payload).unwrap();
        assert_eq!(crypto.payload(&plain_data), Some(payload));
    }

    #[test]
    fn test_package_unpackage() {
        let crypto = Crypto::new(create_keys());
        let payload = b"Hello, world!".as_slice();

        let encoded = crypto.package(payload, None).unwrap();
        assert_ne!(encoded, "");

        let decoded = crypto.unpackage(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_package_unpackage_with_iv() {
        let crypto = Crypto::new(create_keys());
        let timestamp = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1);
        let iv = crypto.create_init_vector(timestamp, 123456789);
        let payload = b"https://example.com".as_slice();

        let encoded = crypto.package(payload, Some(&iv)).unwrap();

        // Metadata is still readable from the base64-encoded package.
        let decoded = crypto.decode(encoded.as_bytes()).unwrap();
        assert_eq!(crypto.timestamp(&decoded), Some(timestamp));
        assert_eq!(crypto.server_id(&decoded), Some(123456789));

        let recovered = crypto.unpackage(&encoded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_package_unpackage_empty_payload() {
        let crypto = Crypto::new(create_keys());
        let payload = b"".as_slice();

        let encoded = crypto.package(payload, None).unwrap();
        let recovered = crypto.unpackage(&encoded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_unpackage_tampered_signature() {
        let crypto = Crypto::new(create_keys());
        let encoded = crypto.package(b"Hello, world!", None).unwrap();

        let mut bytes = crypto.decode(encoded.as_bytes()).unwrap();
        let last = bytes.len() - Crypto::SIGNATURE_SIZE;
        crypto.write_i32(&mut bytes, last, 123456789);

        let tampered = crypto.encode(&bytes);
        assert!(matches!(
            crypto.unpackage(&tampered),
            Err(CryptoError::InvalidSign)
        ));
    }

    #[test]
    fn test_package_to_matches_package() {
        let crypto = Crypto::new(create_keys());
        let timestamp = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1);
        let iv = crypto.create_init_vector(timestamp, 123456789);
        let payload = b"https://example.com".as_slice();

        // Same IV + payload must yield identical output.
        let encoded_alloc = crypto.package(payload, Some(&iv)).unwrap();

        let mut buf = Vec::new();
        crypto.package_to(payload, Some(&iv), &mut buf).unwrap();
        assert_eq!(buf, encoded_alloc.as_bytes());
    }

    #[test]
    fn test_package_to_unpackage_to_roundtrip() {
        let crypto = Crypto::new(create_keys());
        let payload = b"Hello, world!".as_slice();

        let mut enc_buf = Vec::new();
        crypto.package_to(payload, None, &mut enc_buf).unwrap();

        let mut dec_buf = Vec::new();
        crypto.unpackage_to(&enc_buf, &mut dec_buf).unwrap();
        assert_eq!(dec_buf, payload);
    }

    #[test]
    fn test_package_to_appends_and_preserves_existing() {
        let crypto = Crypto::new(create_keys());
        let payload = b"Hello".as_slice();

        let mut buf = b"prefix".to_vec();
        let prefix_len = buf.len();
        crypto.package_to(payload, None, &mut buf).unwrap();

        // Existing bytes are preserved; encoded output is appended.
        assert_eq!(&buf[..prefix_len], b"prefix");
        assert!(buf.len() > prefix_len);

        let mut dec_buf = Vec::new();
        crypto.unpackage_to(&buf[prefix_len..], &mut dec_buf).unwrap();
        assert_eq!(dec_buf, payload);
    }

    #[test]
    fn test_package_to_empty_payload() {
        let crypto = Crypto::new(create_keys());

        let mut enc_buf = Vec::new();
        crypto.package_to(b"", None, &mut enc_buf).unwrap();

        let mut dec_buf = Vec::new();
        crypto.unpackage_to(&enc_buf, &mut dec_buf).unwrap();
        assert_eq!(dec_buf, b"");
    }

    #[test]
    fn test_unpackage_to_tampered_signature() {
        let crypto = Crypto::new(create_keys());

        let mut enc_buf = Vec::new();
        crypto.package_to(b"Hello", None, &mut enc_buf).unwrap();

        // Tamper via the allocating decode/encode helpers, then feed the
        // streaming unpackage path.
        let mut raw = crypto.decode(&enc_buf).unwrap();
        let last = raw.len() - Crypto::SIGNATURE_SIZE;
        crypto.write_i32(&mut raw, last, 123456789);
        let tampered = crypto.encode(&raw);

        let mut dec_buf = Vec::new();
        assert!(matches!(
            crypto.unpackage_to(tampered.as_bytes(), &mut dec_buf),
            Err(CryptoError::InvalidSign)
        ));
    }

    #[test]
    fn test_package_to_with_non_vec_writer() {
        // Exercises the generic `io::Write` path through a writer whose
        // `Write` impl is not `Vec<u8>`'s (BufWriter buffers, then flushes).
        let crypto = Crypto::new(create_keys());
        let payload = b"Hello, world!".as_slice();

        let mut writer = std::io::BufWriter::new(Vec::<u8>::new());
        crypto.package_to(payload, None, &mut writer).unwrap();
        let encoded = writer.into_inner().unwrap();

        let mut dec_buf = Vec::new();
        crypto.unpackage_to(&encoded, &mut dec_buf).unwrap();
        assert_eq!(dec_buf, payload);
    }

    #[test]
    fn test_unpackage_to_appends_to_existing_buffer() {
        // Symmetric to `test_package_to_appends_and_preserves_existing`:
        // unpackage_to must append, not overwrite.
        let crypto = Crypto::new(create_keys());
        let payload = b"Hello".as_slice();
        let encoded = crypto.package(payload, None).unwrap();

        let mut buf = b"prefix".to_vec();
        let prefix_len = buf.len();
        crypto.unpackage_to(&encoded, &mut buf).unwrap();

        assert_eq!(&buf[..prefix_len], b"prefix");
        assert_eq!(&buf[prefix_len..], payload);
    }
}
