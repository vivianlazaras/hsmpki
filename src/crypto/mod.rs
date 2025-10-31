//! Asymmetric Key Abstraction Layer
//!
//! This module defines traits and structures for generating and managing asymmetric
//! key pairs within a PKCS#11 environment. It provides reusable abstractions for
//! different algorithms (e.g., RSA, ECDSA) while maintaining type safety and
//! algorithm-specific templates.
//!
//! Implementations of [`AsymKey`] (such as [`rsa_impl`]) define how to construct
//! key generation templates, determine signature mechanisms, and convert between
//! HSM attributes and high-level key representations.

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::Session;
use uuid::Uuid;

use crate::errors::HsmPkiErr;

pub mod rsa_impl;

#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub extractable: bool, // sets Extractable(), and NeverExtractable()
    pub destroyable: bool,
    pub modifiable: bool,
    pub sensitive: bool,
    pub private: bool,
}

impl KeyConfig {
    pub fn into_attrs(&self) -> Vec<Attribute> {
        vec![
            Attribute::Extractable(self.extractable),
            Attribute::NeverExtractable(self.extractable),
            Attribute::Destroyable(self.destroyable),
            Attribute::Modifiable(self.modifiable),
            Attribute::Sensitive(self.sensitive),
            Attribute::Private(self.private),
        ]
    }
}

impl Default for KeyConfig {
    fn default() -> KeyConfig {
        KeyConfig {
            extractable: false,
            destroyable: false,
            modifiable: false,
            sensitive: true,
            private: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyGenConfig {
    pub name: Option<String>,
    pub privkey: KeyConfig,
    pub pubkey: KeyConfig,
}

impl Default for KeyGenConfig {
    fn default() -> Self {
        let pubkey = KeyConfig {
            extractable: true,
            destroyable: false,
            modifiable: false,
            sensitive: false,
            private: false,
        };
        Self {
            name: None,
            privkey: KeyConfig::default(),
            pubkey,
        }
    }
}

/// Represents a generated key pair stored in the HSM.
///
/// A [`KeyPair`] contains both public and private key handles, along with unique
/// identifiers (UUIDs) that can be used to correlate the logical keys with
/// metadata, certificates, or external registries.
///
/// # Fields
/// * `pubkeyid` — Unique identifier for the public key.
/// * `privkeyid` — Unique identifier for the private key.
/// * `pubkey_handle` — PKCS#11 handle for the public key object.
/// * `privkey_handle` — PKCS#11 handle for the private key object.
///
/// # Example
/// ```no_run
/// let pair = key_impl.generate(&session)?;
/// println!("Generated keypair: pub={}, priv={}", pair.pubkeyid, pair.privkeyid);
/// ```
pub struct KeyPair {
    pub pubkey_handle: ObjectHandle,
    pub privkey_handle: ObjectHandle,
}

/// Defines the behavior of an asymmetric key generator.
///
/// Implementors of this trait (e.g., RSA, ECDSA) specify how to construct the
/// attribute templates required for key pair generation on the HSM.  
/// The `generate` method provides a standardized way to produce and return
/// a [`KeyPair`] object.
///
/// # Associated Types
/// * `PubKey`: The corresponding public key type implementing [`PublicKey`].
///
/// # Example
/// ```no_run
/// struct MyRsaKey;
/// impl AsymKey for MyRsaKey {
///     type PubKey = RsaPubKey;
///     fn pubkey_template(&self) -> Vec<Attribute> { /* ... */ }
///     fn privkey_template(&self) -> Vec<Attribute> { /* ... */ }
///     fn mechanism(&self) -> Mechanism { Mechanism::RsaPkcsKeyPairGen }
/// }
/// ```
pub trait AsymKey {
    /// The type representing the corresponding public key.
    type PubKey: PublicKey;

    /// Constructs the public key attribute template for key generation.
    ///
    /// Returns `attributes` where:
    /// - `attributes` defines PKCS#11 attributes like `CKA_LABEL`, `CKA_PUBLIC_EXPONENT`, etc.
    fn pubkey_template() -> Vec<Attribute>;

    /// Constructs the private key attribute template for key generation.
    ///
    /// Returns `attributes` where:
    /// - `attributes` specifies properties such as `CKA_SENSITIVE`, `CKA_SIGN`, etc.
    fn privkey_template() -> Vec<Attribute>;

    /// Returns the PKCS#11 mechanism used for this key type’s generation.
    ///
    /// For RSA, this would be `Mechanism::RsaPkcsKeyPairGen`.
    fn mechanism() -> Mechanism<'static>;

    /// Generates a new keypair, then uses the HSM to compute a hash of the
    /// public key (via `C_DigestKey`) to use as the `CKA_ID` for both keys.
    ///
    /// # Process
    /// 1. Generate the keypair with `C_GenerateKeyPair`.
    /// 2. Initialize a digest operation (`C_DigestInit`).
    /// 3. Hash the public key object directly (`C_DigestKey`).
    /// 4. Finalize the digest (`C_DigestFinal`) to get a key ID.
    /// 5. Write the resulting digest to both public and private keys as `CKA_ID`.
    ///
    /// # Returns
    /// A [`KeyPair`] containing object handles for the generated keys.
    ///
    /// # Errors
    /// Returns [`HsmPkiErr`] if key generation, digest operations,
    /// or attribute updates fail.
    fn generate(session: &Session, hash_alg: HashAlg, config: Option<KeyGenConfig>) -> Result<KeyPair, HsmPkiErr> {
        let mechanism = Self::mechanism();
        let pubkey = Self::pubkey_template();
        let privkey = Self::privkey_template();
        let (privkey_handle, pubkey_handle) =
            session.generate_key_pair(&mechanism, &pubkey, &privkey)?;

        let digest_mech: Mechanism = hash_alg.into();
        session.digest_init(&digest_mech)?;

        // 3. Compute digest directly over the key object in the HSM
        session.digest_key(pubkey_handle)?;

        // 4. Finalize digest to retrieve computed hash
        let id_hash = session.digest_final()?;

        // 5. Assign computed hash as CKA_ID for both public and private keys
        let id_attr = Attribute::Id(id_hash.clone());
        let mut pubkey_attrs = Vec::new();
        let mut privkey_attrs = Vec::new();

        pubkey_attrs.push(id_attr.clone());
        privkey_attrs.push(id_attr);

        if let Some(config) = config {
            pubkey_attrs.extend_from_slice(&config.pubkey.into_attrs());
            privkey_attrs.extend_from_slice(&config.privkey.into_attrs());
        }

        let new_pub = session.copy_object(pubkey_handle, &pubkey_attrs)?;
        let new_priv = session.copy_object(privkey_handle, &privkey_attrs)?;

        // Destroy the originals (optional but recommended)
        session.destroy_object(pubkey_handle)?;
        session.destroy_object(privkey_handle)?;

        Ok(KeyPair {
            privkey_handle: new_priv,
            pubkey_handle: new_pub,
        })
    }
}

/// Describes the behavior of a public key object derived from an HSM.
///
/// This trait generalizes over different asymmetric key algorithms, providing
/// methods to identify the key, determine its signature algorithm, and reconstruct
/// it from raw PKCS#11 attributes.
///
/// Implementors are expected to define how to:
/// - Derive an internal identifier (`Uuid`)
/// - Provide required attributes
/// - Decode attributes back into structured key data
///
/// # Example
/// ```no_run
/// let attrs = session.get_attributes(pubkey_handle, RsaPubKey::required_attributes())?;
/// let pubkey = RsaPubKey::from_attributes(&attrs)?;
/// ```
pub trait PublicKey: rcgen::PublicKeyData + Sized {
    /// Returns the unique identifier (UUID) for this key object.
    fn pubkey_id(&self) -> Uuid;

    /// Returns the signature algorithm associated with this public key.
    ///
    /// Used for mapping to [`rcgen::SignatureAlgorithm`] or PKCS#11 [`Mechanism`].
    fn sigalg(&self) -> SigAlg;

    /// Returns a generic attribute template for creating a new public key.
    ///
    /// Implementations may define static templates or parameterized templates.
    fn template() -> Vec<Attribute>;

    /// Returns the list of required PKCS#11 attribute types needed to reconstruct this key.
    ///
    /// For RSA, this might include `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`.
    fn required_attributes() -> Vec<AttributeType>;

    /// Constructs the public key from a set of PKCS#11 attributes.
    ///
    /// # Errors
    /// Returns [`HsmPkiErr::MissingPubKeyAttribute`] if a required attribute is absent.
    fn from_attributes(attr: &[Attribute]) -> Result<Self, HsmPkiErr>;
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl<'a> From<HashAlg> for Mechanism<'a> {
    fn from(hash: HashAlg) -> Mechanism<'a> {
        match hash {
            HashAlg::Sha1 => Mechanism::Sha1,
            HashAlg::Sha224 => Mechanism::Sha224,
            HashAlg::Sha256 => Mechanism::Sha256,
            HashAlg::Sha384 => Mechanism::Sha384,
            HashAlg::Sha512 => Mechanism::Sha512,
        }
    }
}

/// Enumerates supported signature algorithms for asymmetric keys.
///
/// Used for mapping between high-level cryptographic algorithms (e.g. `rcgen`),
/// PKCS#11 mechanisms, and bit-length–based key characteristics.
///
/// # Variants
/// - `RSASha256` — For 2048-bit RSA keys
/// - `RSASha384` — For 3072-bit RSA keys
/// - `RSASha512` — For 4096-bit or higher RSA keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    /// RSA key with SHA-256 hashing (commonly used with 2048-bit keys).
    RSASha256,
    /// RSA key with SHA-384 hashing (commonly used with 3072-bit keys).
    RSASha384,
    /// RSA key with SHA-512 hashing (commonly used with 4096-bit or larger keys).
    RSASha512,
}

impl SigAlg {
    /// Infers the appropriate signature algorithm based on RSA key size (in bits).
    ///
    /// # Example
    /// ```
    /// assert_eq!(SigAlg::from_rsa_key_bits(2048), Some(SigAlg::RSASha256));
    /// ```
    pub(crate) fn from_rsa_key_bits(bits: usize) -> Option<Self> {
        match bits {
            2048 => Some(SigAlg::RSASha256), // 2048-bit → SHA-256
            3072 => Some(SigAlg::RSASha384), // 3072-bit → SHA-384
            4096 => Some(SigAlg::RSASha512), // 4096-bit → SHA-512
            _ => None,
        }
    }
}

impl From<SigAlg> for &'static rcgen::SignatureAlgorithm {
    /// Converts this [`SigAlg`] to the corresponding `rcgen` signature algorithm reference.
    fn from(sig: SigAlg) -> &'static rcgen::SignatureAlgorithm {
        match sig {
            SigAlg::RSASha256 => &rcgen::PKCS_RSA_SHA256,
            SigAlg::RSASha384 => &rcgen::PKCS_RSA_SHA384,
            SigAlg::RSASha512 => &rcgen::PKCS_RSA_SHA512,
        }
    }
}

impl<'a> From<SigAlg> for Mechanism<'a> {
    /// Converts this [`SigAlg`] into the corresponding PKCS#11 [`Mechanism`]
    /// used for signing operations.
    fn from(sig: SigAlg) -> Mechanism<'a> {
        match sig {
            SigAlg::RSASha256 => Mechanism::Sha256RsaPkcs,
            SigAlg::RSASha384 => Mechanism::Sha384RsaPkcs,
            SigAlg::RSASha512 => Mechanism::Sha512RsaPkcs,
        }
    }
}
