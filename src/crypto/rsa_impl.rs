use super::{PublicKey, SigAlg};
use crate::crypto::AsymKey;
use crate::errors::HsmPkiErr;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::object::AttributeType;
use cryptoki::session::Session;
use rcgen::PublicKeyData;
use rcgen::SignatureAlgorithm;
use rcgen::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use uuid::Uuid;

use rsa::BigUint;

pub struct RsaKey<'a, P: PublicKey> {
    id: String,
    pubkey: P,
    session: &'a Session,
}

impl<'a, P: PublicKey> PublicKeyData for RsaKey<'a, P> {
    fn der_bytes(&self) -> &[u8] {
        self.pubkey.der_bytes()
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &self.pubkey.algorithm()
    }
}

impl<'a, P: PublicKey> SigningKey for RsaKey<'a, P> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let attrs = vec![Attribute::Id(self.id.as_bytes().to_vec())];
        let mut objects = self
            .session
            .find_objects(&attrs)
            .expect("failed to get objects");
        if objects.len() != 1 {
            panic!("multiple objects found");
        }
        let key = objects.pop().expect("empty key");
        let mechanism: Mechanism = self.pubkey.sigalg().into();
        Ok(self
            .session
            .sign(&mechanism, key, msg)
            .expect("failed to sign"))
    }
}

impl<'a, P: PublicKey> AsymKey for RsaKey<'a, P> {
    type PubKey = P;
    fn pubkey_template() -> Vec<Attribute> {
        P::template()
    }

    fn privkey_template() -> Vec<Attribute> {
        vec![Attribute::Token(true), Attribute::Private(false)]
    }

    fn mechanism() -> Mechanism<'static> {
        Mechanism::RsaPkcsKeyPairGen
    }
}

#[derive(Clone, Debug)]
pub struct RsaPubKey {
    id: Uuid,
    sigalg: SigAlg,
    // der encoded vector of pubkey bytes in SPKI format.
    pubkey: Vec<u8>,
}

impl PublicKeyData for RsaPubKey {
    fn der_bytes(&self) -> &[u8] {
        &self.pubkey
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.sigalg.into()
    }
}

impl PublicKey for RsaPubKey {
    fn pubkey_id(&self) -> Uuid {
        self.id
    }
    fn sigalg(&self) -> SigAlg {
        self.sigalg
    }
    fn template() -> Vec<Attribute> {
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::ModulusBits(1024.into()),
        ]
    }
    fn required_attributes() -> Vec<AttributeType> {
        vec![
            AttributeType::Id,
            AttributeType::Modulus,
            AttributeType::PublicExponent,
        ]
    }
    fn from_attributes(attrs: &[Attribute]) -> Result<Self, HsmPkiErr> {
        let mut n: Option<BigUint> = None;
        let mut e: Option<BigUint> = None;
        let mut id_opt: Option<Uuid> = None;
        for attr in attrs.iter() {
            match attr {
                Attribute::Modulus(modulus) => n = Some(BigUint::from_bytes_be(&modulus)),
                Attribute::PublicExponent(exp) => e = Some(BigUint::from_bytes_be(&exp)),
                Attribute::Id(id_attr) => {
                    id_opt = Some(Uuid::from_bytes(id_attr.as_slice().try_into()?))
                }
                _ => return Err(HsmPkiErr::UnexpectedAttribute),
            }
        }
        if n.is_none() || e.is_none() || id_opt.is_none() {
            return Err(HsmPkiErr::MissingPubKeyAttribute);
        }
        let n = n.unwrap();
        let bits = n.bits();
        let sig_alg_opt = SigAlg::from_rsa_key_bits(bits as usize);
        if sig_alg_opt.is_none() {
            return Err(HsmPkiErr::InvalidKeyBits(bits));
        }

        let public_key = rsa::RsaPublicKey::new(n, e.unwrap())?;
        let der = public_key.to_public_key_der()?;
        let pubkey = der.into_vec();
        Ok(Self {
            id: id_opt.unwrap(),
            sigalg: sig_alg_opt.unwrap(),
            pubkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::HsmPkiErr;
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::object::AttributeType;
    use rand::rngs::OsRng;
    use rsa::BigUint;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
    use uuid::Uuid;

    // Helper to build attribute vec from an rsa::RsaPublicKey and id
    fn build_attrs_from_rsa_pubkey(pubkey: &RsaPublicKey, id: Uuid) -> Vec<Attribute> {
        let n = pubkey.n().to_bytes_be();
        let e = pubkey.e().to_bytes_be();
        vec![
            Attribute::Id(id.as_bytes().to_vec()),
            Attribute::Modulus(n),
            Attribute::PublicExponent(e),
        ]
    }

    #[test]
    fn test_sigalg_from_bits_known_mappings() {
        assert_eq!(SigAlg::from_rsa_key_bits(2048), Some(SigAlg::RSASha256));
        assert_eq!(SigAlg::from_rsa_key_bits(3072), Some(SigAlg::RSASha384));
        assert_eq!(SigAlg::from_rsa_key_bits(4096), Some(SigAlg::RSASha512));
        assert_eq!(SigAlg::from_rsa_key_bits(1024), None);
        assert_eq!(SigAlg::from_rsa_key_bits(12345), None);
    }

    #[test]
    fn test_sigalg_into_rcgen_signaturealgorithm_ptrs_match() {
        // Compare pointer addresses of the static rcgen signature algorithm values
        let s256: &'static rcgen::SignatureAlgorithm = SigAlg::RSASha256.into();
        let s384: &'static rcgen::SignatureAlgorithm = SigAlg::RSASha384.into();
        let s512: &'static rcgen::SignatureAlgorithm = SigAlg::RSASha512.into();

        let pkcs256_ptr = &rcgen::PKCS_RSA_SHA256 as *const _;
        let pkcs384_ptr = &rcgen::PKCS_RSA_SHA384 as *const _;
        let pkcs512_ptr = &rcgen::PKCS_RSA_SHA512 as *const _;

        assert_eq!(s256 as *const _, pkcs256_ptr);
        assert_eq!(s384 as *const _, pkcs384_ptr);
        assert_eq!(s512 as *const _, pkcs512_ptr);
    }

    #[test]
    fn test_sigalg_into_mechanism_matches_expected() {
        let m256: Mechanism = SigAlg::RSASha256.into();
        let m384: Mechanism = SigAlg::RSASha384.into();
        let m512: Mechanism = SigAlg::RSASha512.into();
    }

    #[test]
    fn test_rsapubkey_from_attributes_success_2048() {
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let attrs = build_attrs_from_rsa_pubkey(&pubkey, id);

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_ok(), "expected Ok for 2048-bit key, got {:?}", res);
        let rsa_pub = res.unwrap();

        assert_eq!(rsa_pub.pubkey_id(), id);
        assert_eq!(rsa_pub.sigalg, SigAlg::RSASha256);

        // The der should match to_public_key_der
        let expected_der = pubkey.to_public_key_der().expect("der encode").into_vec();
        assert_eq!(rsa_pub.der_bytes(), expected_der.as_slice());
    }

    #[test]
    fn test_rsapubkey_from_attributes_success_3072() {
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 3072).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let attrs = build_attrs_from_rsa_pubkey(&pubkey, id);

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_ok(), "expected Ok for 3072-bit key, got {:?}", res);
        let rsa_pub = res.unwrap();

        assert_eq!(rsa_pub.pubkey_id(), id);
        assert_eq!(rsa_pub.sigalg, SigAlg::RSASha384);

        let expected_der = pubkey.to_public_key_der().expect("der encode").into_vec();
        assert_eq!(rsa_pub.der_bytes(), expected_der.as_slice());
    }

    #[test]
    fn test_rsapubkey_from_attributes_success_4096() {
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 4096).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let attrs = build_attrs_from_rsa_pubkey(&pubkey, id);

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_ok(), "expected Ok for 4096-bit key, got {:?}", res);
        let rsa_pub = res.unwrap();

        assert_eq!(rsa_pub.pubkey_id(), id);
        assert_eq!(rsa_pub.sigalg, SigAlg::RSASha512);

        let expected_der = pubkey.to_public_key_der().expect("der encode").into_vec();
        assert_eq!(rsa_pub.der_bytes(), expected_der.as_slice());
    }

    #[test]
    fn test_rsapubkey_from_attributes_missing_attribute_error() {
        // generate a valid pubkey but omit the exponent
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let attrs = vec![
            Attribute::Id(id.as_bytes().to_vec()),
            Attribute::Modulus(pubkey.n().to_bytes_be()),
            // no PublicExponent attribute
        ];

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_err());
        match res.err().unwrap() {
            HsmPkiErr::MissingPubKeyAttribute => {}
            other => panic!("expected MissingPubKeyAttribute, got {:?}", other),
        }
    }

    #[test]
    fn test_rsapubkey_from_attributes_unexpected_attribute_error() {
        // generate a valid pubkey but add an unexpected attribute (Token)
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let mut attrs = build_attrs_from_rsa_pubkey(&pubkey, id);
        // insert an unexpected attribute; code should return UnexpectedAttribute
        attrs.push(Attribute::Token(true));

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_err());
        match res.err().unwrap() {
            HsmPkiErr::UnexpectedAttribute => {}
            other => panic!("expected UnexpectedAttribute, got {:?}", other),
        }
    }

    #[test]
    fn test_rsapubkey_from_attributes_invalid_bits_error() {
        // generate a 1024-bit RSA key which is not supported by from_rsa_key_bits mapping
        let mut rng = OsRng;
        // Note: rsa crate still allows 1024 but it's small; we expect InvalidKeyBits
        let privkey = RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate key");
        let pubkey = RsaPublicKey::from(&privkey);

        let id = Uuid::new_v4();
        let attrs = build_attrs_from_rsa_pubkey(&pubkey, id);

        let res = RsaPubKey::from_attributes(&attrs);
        assert!(res.is_err());
        match res.err().unwrap() {
            HsmPkiErr::InvalidKeyBits(bits) => {
                // bits should equal the modulus bits (1024)
                assert_eq!(bits, pubkey.n().bits() as usize);
            }
            other => panic!("expected InvalidKeyBits, got {:?}", other),
        }
    }

    #[test]
    fn test_rsapubkey_publickeydata_der_and_algorithm() {
        // construct an RsaPubKey manually and inspect der_bytes() and algorithm()
        let mut rng = OsRng;
        let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to create");
        let pubkey = RsaPublicKey::from(&privkey);
        let id = Uuid::new_v4();
        let der = pubkey.to_public_key_der().expect("der").into_vec();

        let rsa_pub = RsaPubKey {
            id,
            sigalg: SigAlg::RSASha256,
            pubkey: der.clone(),
        };

        assert_eq!(rsa_pub.der_bytes(), der.as_slice());

        // algorithm() returns a static rcgen::SignatureAlgorithm reference
        let alg = rsa_pub.algorithm();
        let expected_alg: &'static rcgen::SignatureAlgorithm = &rcgen::PKCS_RSA_SHA256;
        assert_eq!(alg as *const _, expected_alg as *const _);
    }

    #[test]
    fn test_required_attributes_list() {
        let req = RsaPubKey::required_attributes();
        // must contain Id, Modulus, PublicExponent (order doesn't matter)
        assert!(req.contains(&AttributeType::Id));
        assert!(req.contains(&AttributeType::Modulus));
        assert!(req.contains(&AttributeType::PublicExponent));
    }

    #[test]
    fn test_template_contains_id_and_modulusbits() {
        let (id, attrs) = RsaPubKey::template();
        // id should match the Attribute::Id in attrs
        let found_id_attr = attrs
            .iter()
            .find_map(|a| {
                if let Attribute::Id(b) = a {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .expect("template must include Id attribute");
        assert_eq!(found_id_attr.as_slice(), id.as_bytes());

        // there should be a ModulusBits attribute (value 1024 in your template)
        let has_modulus_bits = attrs.iter().any(|a| matches!(a, Attribute::ModulusBits(_)));
        assert!(has_modulus_bits);
    }
}
