//! Error types for HSM PKI session and cryptographic operations.
//!
//! This module defines the [`HsmPkiErr`] enum, a unified error type that
//! wraps low-level cryptographic, PKCS#11, and concurrency-related errors.
//!
//! It provides detailed error conversion through `thiserror::Error` so that
//! calling functions can transparently propagate errors using the `?` operator.

use thiserror::Error;

/// Unified error type for all HSM PKI operations.
///
/// This enum aggregates errors from several layers of the system:
/// - PKCS#11 interaction failures
/// - Asynchronous concurrency issues (e.g., semaphore acquisition)
/// - Cryptographic library errors (X.509, RSA, etc.)
/// - Data validation or conversion errors
///
/// Most variants implement `From` conversions automatically through `thiserror`,
/// enabling ergonomic error propagation from lower-level calls.
///
/// # Example
/// ```
/// fn example() -> Result<(), HsmPkiErr> {
///     // Any underlying error from cryptoki, RSA, etc. can bubble up directly
///     // thanks to `#[from]` on the respective variants.
///     Err(HsmPkiErr::InvalidKeyBits(1024))
/// }
/// ```
#[derive(Debug, Error)]
pub enum HsmPkiErr {
    /// Represents an error originating from the underlying PKCS#11 library (`cryptoki`).
    ///
    /// This occurs when a low-level operation (e.g., `open_session`, `login`, `find_objects`)
    /// fails according to the PKCS#11 module or driver.
    ///
    /// Wraps [`cryptoki::error::Error`].
    #[error("cryptoki error: {0}")]
    CryptoKiErr(#[from] cryptoki::error::Error),

    /// Raised when a semaphore permit cannot be acquired in an async context.
    ///
    /// This can happen if the semaphore has been closed, or if there’s a logic
    /// error in the session pool preventing permit acquisition.
    ///
    /// Wraps [`tokio::sync::AcquireError`].
    #[error("failed to acquire semaphore permit: {0}")]
    AcquireErr(#[from] tokio::sync::AcquireError),

    /// Indicates a failure parsing or handling X.509 certificate or SPKI structures.
    ///
    /// This often occurs during subject public key extraction, signature validation,
    /// or DER decoding when working with the [`x509-cert`](https://docs.rs/x509-cert)
    /// crate.
    ///
    /// Wraps [`x509_cert::spki::Error`].
    #[error("certificate error: {0}")]
    X509Err(#[from] x509_cert::spki::Error),

    /// Indicates a cryptographic error from the RSA crate.
    ///
    /// This may occur during key import/export, encryption/decryption, or
    /// signature generation/verification.
    ///
    /// Wraps [`rsa::Error`].
    #[error("rsa error: {0}")]
    RSAError(#[from] rsa::Error),

    /// Returned when a required PKCS#11 public key attribute (e.g., modulus, exponent)
    /// is missing from an object template.
    ///
    /// This can indicate a malformed or incomplete key object in the HSM.
    #[error("missing required pubkey attribute")]
    MissingPubKeyAttribute,

    /// Returned when an unexpected PKCS#11 attribute is encountered while parsing
    /// or processing an object template.
    ///
    /// Often indicates schema mismatch or token configuration errors.
    #[error("unexpected attribute")]
    UnexpectedAttribute,

    /// Returned when an RSA key’s bit length does not match expected or supported values.
    ///
    /// This variant includes the invalid bit length as context.
    #[error("invalid bits length: {0}")]
    InvalidKeyBits(usize),

    /// Raised when converting a byte slice to a fixed-size array fails.
    ///
    /// This is typically used when parsing DER-encoded or PKCS#11 attribute data
    /// that must fit into a statically sized structure.
    ///
    /// Wraps [`std::array::TryFromSliceError`].
    #[error("try from slice error: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
}
