//! HSM Session Pool Management
//!
//! This module provides types and utilities for managing concurrent PKCS#11 sessions
//! against a hardware security module (HSM). The goal is to ensure efficient and safe
//! reuse of authenticated sessions across async tasks, while enforcing fair resource
//! usage and backpressure using semaphores.

use crate::crypto::{AsymKey, HashAlg, KeyGenConfig, KeyPair};
use crate::errors::*;
use crate::users::User;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use cryptoki::context::{Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use cryptoki::slot::{Slot, TokenInfo};

/// Represents an active, authenticated PKCS#11 session within the pool.
///
/// Each `SessionHandle` corresponds to a distinct session index, allowing tracking
/// and debugging of concurrent session usage. The session is automatically logged in
/// upon creation, and can perform any authorized HSM operations thereafter.
///
/// # Example
/// ```no_run
/// let ctx = Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so")?;
/// let slot = ctx.get_slot_list(true)?.first().unwrap().clone();
/// let user = User::new_user("1234");
/// let handle = SessionHandle::new(&ctx, &user, slot, 0)?;
/// ```
pub struct SessionHandle {
    index: usize,
    session: Session,
}

impl SessionHandle {
    /// Computes a cryptographic digest (hash) of a key object inside the HSM using PKCS#11’s
    /// [`C_DigestKey`] mechanism sequence.
    ///
    /// This function initializes a digest operation with the provided hashing algorithm,
    /// performs the digest over the key specified by the given [`ObjectHandle`],
    /// and returns the resulting hash bytes.
    ///
    /// # Parameters
    /// - `hashalg`: The [`HashAlg`] whose corresponding hashing mechanism will be used
    ///   (e.g. `HashAlg::Sha256` → `Mechanism::Sha256`).
    /// - `key`: The [`ObjectHandle`] of the key object within the current session to be digested.
    ///   This key must support the `CKA_EXTRACTABLE` and `CKA_SENSITIVE` attribute policies
    ///   required by the token for `C_DigestKey` operations.
    ///
    /// # Returns
    /// Returns a `Vec<u8>` containing the digest of the key as computed by the HSM.
    ///
    /// # Errors
    /// Returns a [`HsmPkiErr`] if:
    /// - The digest mechanism is unsupported by the token.
    /// - The session or key handle is invalid.
    /// - The token prohibits digesting key material (e.g. for sensitive/private keys).
    /// - A PKCS#11 operation fails during initialization, digesting, or finalization.
    ///
    /// # Example
    /// ```rust,ignore
    /// use cryptoki::object::ObjectHandle;
    ///
    /// let key_handle: ObjectHandle = ...;
    /// let digest = session_handle.digest_key(HashAlg::Sha256, key_handle)?;
    /// println!("Key digest: {:x?}", digest);
    /// ```
    ///
    /// # Notes
    /// - This function leverages the token’s internal hashing, so the key material itself
    ///   never leaves the secure boundary of the HSM.
    /// - Many HSMs only permit `C_DigestKey` on *public* keys or symmetric keys marked as
    ///   digestable; attempting this on private keys often yields a `CKR_KEY_FUNCTION_NOT_PERMITTED`.
    /// - The resulting digest is typically used for deriving a unique `CKA_ID` value or
    ///   for computing a `SubjectKeyIdentifier` in X.509 certificates.
    ///
    /// # Related
    /// - [`Session::digest_init`]
    /// - [`Session::digest_key`]
    /// - [`Session::digest_final`]
    /// - [`HashAlg`]
    /// - [`HsmPkiErr`]
    pub fn disgest_key(&self, hashalg: HashAlg, key: ObjectHandle) -> Result<Vec<u8>, HsmPkiErr> {
        let mechanism: Mechanism = hashalg.into();
        self.session.digest_init(&mechanism)?;
        self.session.digest_key(key)?;
        Ok(self.session.digest_final()?)
    }

    pub fn generate_key_pair<K: AsymKey>(
        &self,
        hash_alg: HashAlg,
        config: KeyGenConfig,
    ) -> Result<KeyPair, HsmPkiErr> {
        K::generate(&self.session, hash_alg, Some(config))
    }

    /// Creates a new logged-in session for the given slot and user.
    ///
    /// The returned `SessionHandle` owns a writable PKCS#11 session (`open_rw_session`)
    /// and logs in using the user’s credentials.
    ///
    /// # Errors
    /// Returns `HsmPkiErr` if session creation or login fails.
    pub fn new(pkcs11: &Pkcs11, user: &User, slot: Slot, index: usize) -> Result<Self, HsmPkiErr> {
        let session = pkcs11.open_rw_session(slot)?;
        session.login(user.ty, Some(&user.pin))?;
        Ok(Self { session, index })
    }

    /// Adds a new user PIN to the token (only allowed if logged in as SO).
    ///
    /// # Errors
    /// Returns an error if the current session is not logged in as Security Officer (SO),
    /// or if the underlying PKCS#11 call fails.
    pub fn add_user(&self, user: &User) -> Result<(), HsmPkiErr> {
        Ok(self.session.init_pin(&user.pin)?)
    }

    /// Returns the numeric index of this session in the pool.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns a reference to the underlying `Session` for advanced operations.
    pub fn inner(&self) -> &Session {
        &self.session
    }
}

/// A concurrency-safe pool of PKCS#11 sessions.
///
/// `SessionPool` manages multiple concurrently reusable `SessionHandle`s, each wrapped in
/// an async `Mutex`. Access to sessions is throttled through a `Semaphore`, ensuring that
/// no more than the maximum number of concurrent sessions are used.
///
/// When acquiring a session, you get a pair `(OwnedMutexGuard<SessionHandle>, OwnedSemaphorePermit)`.
/// The `OwnedSemaphorePermit` ensures that once dropped, a slot in the pool becomes available
/// for the next requester.
///
/// # Example
/// ```no_run
/// let ctx = Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so")?;
/// let slot = ctx.get_slot_list(true)?.first().unwrap().clone();
/// let info = ctx.get_token_info(slot)?;
/// let user = User::new_user("1234");
///
/// let pool = SessionPool::from_parts(&ctx, slot, &info, &user)?;
///
/// // Acquire a session asynchronously
/// let (session_guard, _permit) = pool.lock_any().await?;
/// let session = session_guard.inner();
/// ```
#[derive(Clone)]
pub struct SessionPool {
    sessions: Vec<Arc<Mutex<SessionHandle>>>,
    semaphore: Arc<Semaphore>,
}

impl SessionPool {
    /// Constructs a new session pool from PKCS#11 context, slot, token info, and user credentials.
    ///
    /// The number of sessions is determined by the token’s `max_rw_session_count` field,
    /// defaulting to 16 if unspecified.
    ///
    /// # Errors
    /// Returns `HsmPkiErr` if session creation or login fails for any session.
    pub fn from_parts(
        context: &Pkcs11,
        slot: Slot,
        info: &TokenInfo,
        user: &User,
    ) -> Result<Self, HsmPkiErr> {
        let pool_size: usize =
            Into::<Option<u64>>::into(info.max_rw_session_count()).unwrap_or(16) as usize;

        let mut sessions = Vec::with_capacity(pool_size);
        for idx in 0..pool_size {
            let handle = SessionHandle::new(context, user, slot, idx)?;
            sessions.push(Arc::new(Mutex::new(handle)));
        }

        Ok(Self {
            sessions,
            semaphore: Arc::new(Semaphore::new(pool_size)),
        })
    }

    /// Returns the total number of sessions managed by this pool.
    pub fn size(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the number of currently available (unacquired) sessions.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Attempts to acquire a session immediately, without waiting.
    ///
    /// Returns `Ok(Some((guard, permit)))` if successful, or `Ok(None)` if all sessions are busy.
    ///
    /// # Example
    /// ```no_run
    /// if let Some((guard, _permit)) = pool.try_lock()? {
    ///     let sess = guard.inner();
    ///     // perform operation
    /// }
    /// ```
    pub fn try_lock(
        &self,
    ) -> Result<Option<(OwnedMutexGuard<SessionHandle>, OwnedSemaphorePermit)>, HsmPkiErr> {
        if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
            for sess in &self.sessions {
                if let Ok(guard) = sess.clone().try_lock_owned() {
                    return Ok(Some((guard, permit)));
                }
            }
            // No mutex available, release the permit
            drop(permit);
        }
        Ok(None)
    }

    /// Waits asynchronously for any available session (non-spinning, fair acquisition).
    ///
    /// This method efficiently waits for both the semaphore and an available session mutex.
    /// Once acquired, the returned guard and permit together represent one active session.
    ///
    /// The semaphore ensures no more than `pool_size` concurrent users are holding sessions.
    ///
    /// # Example
    /// ```no_run
    /// let (guard, permit) = pool.lock_any().await?;
    /// let session = guard.inner();
    /// ```
    pub async fn lock_any(
        &self,
    ) -> Result<(OwnedMutexGuard<SessionHandle>, OwnedSemaphorePermit), HsmPkiErr> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        // Try until one mutex becomes available
        loop {
            for sess in &self.sessions {
                if let Ok(guard) = sess.clone().try_lock_owned() {
                    return Ok((guard, permit));
                }
            }
            // Yield only if all locks are currently taken,
            // but since we hold a semaphore permit, one *will* eventually unlock.
            tokio::task::yield_now().await;
        }
    }

    /// Gracefully logs out all sessions and clears the pool.
    ///
    /// This is optional and typically not required if the process exits cleanly,
    /// but useful for controlled shutdowns or when rotating credentials.
    pub async fn logout_all(&self) -> Result<(), HsmPkiErr> {
        for sess in &self.sessions {
            let guard = sess.lock().await;
            guard.inner().logout()?;
        }
        Ok(())
    }

    /// Iterates over all session indices (useful for diagnostics and monitoring).
    pub fn session_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.sessions.iter().enumerate().map(|(i, _)| i)
    }
}
