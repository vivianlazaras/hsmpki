# Hardware Security Module Public Key Infrastructre (HSMPKI)
This crate aims to provide an implementation of an HSM backed local CA that can issue signed certificates with an HSM backing to devices on a local area network.

This would allow automatic domain name allocation based on public key hashing, and signature issuance to registered services on the local area network.

## Future Plan
An authorizer should exist that can prompt an administrator on a trusted device for approval when creating a new certificate. 