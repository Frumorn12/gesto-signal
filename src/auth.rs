//! Proof that a peer owns the host fingerprint it claims.
//!
//! The signaling server is deliberately not a trusted party: it cannot decrypt
//! Waypad sessions and holds no secrets belonging to a host. It only needs
//! enough authentication to stop an attacker from squatting on someone else's
//! fingerprint and intercepting connection attempts. The daemon already owns a
//! P-256 ECDSA identity, so the same key proves ownership here.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey},
};
use thiserror::Error;

use crate::protocol::REGISTER_TRANSCRIPT_PREFIX;

const NONCE_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("malformed base64 in {field}")]
    Base64 { field: &'static str },
    #[error("fingerprint does not match the supplied public key")]
    FingerprintMismatch,
    #[error("signature does not verify against the supplied public key")]
    BadSignature,
    #[error("failed to generate a challenge nonce")]
    Rng,
}

pub fn random_nonce() -> Result<Vec<u8>, AuthError> {
    let mut bytes = vec![0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AuthError::Rng)?;
    Ok(bytes)
}

pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn decode(data: &str, field: &'static str) -> Result<Vec<u8>, AuthError> {
    STANDARD
        .decode(data)
        .map_err(|_| AuthError::Base64 { field })
}

/// Recomputes the Waypad host fingerprint: SHA-256 hex, grouped in fours.
///
/// This must stay byte-for-byte identical to `crypto::fingerprint` in the
/// daemon, otherwise a host could never register.
pub fn fingerprint(public_key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, public_key);
    let hex = hex::encode(digest.as_ref());
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The bytes a host signs to prove it holds the private key for `fingerprint`.
pub fn register_transcript(fingerprint: &str, nonce: &[u8]) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(REGISTER_TRANSCRIPT_PREFIX.len() + fingerprint.len() + nonce.len());
    transcript.extend_from_slice(REGISTER_TRANSCRIPT_PREFIX);
    transcript.extend_from_slice(fingerprint.as_bytes());
    transcript.extend_from_slice(nonce);
    transcript
}

/// Checks that `public_key` really hashes to `claimed_fingerprint`.
pub fn verify_fingerprint(claimed_fingerprint: &str, public_key: &[u8]) -> Result<(), AuthError> {
    if fingerprint(public_key) == claimed_fingerprint {
        Ok(())
    } else {
        Err(AuthError::FingerprintMismatch)
    }
}

/// Checks the ECDSA signature over the registration transcript.
pub fn verify_registration(
    public_key: &[u8],
    claimed_fingerprint: &str,
    nonce: &[u8],
    signature: &[u8],
) -> Result<(), AuthError> {
    let transcript = register_transcript(claimed_fingerprint, nonce);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&transcript, signature)
        .map_err(|_| AuthError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    fn keypair() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    #[test]
    fn fingerprint_is_grouped_sha256_hex() {
        let fp = fingerprint(b"abc");
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert!(fp.starts_with("ba78:16bf:8f01:cfea:"));
        assert_eq!(fp.matches(':').count(), 15);
        assert_eq!(fp.len(), 64 + 15);
    }

    #[test]
    fn accepts_a_signature_from_the_matching_key() {
        let rng = SystemRandom::new();
        let key = keypair();
        let public_key = key.public_key().as_ref().to_vec();
        let fp = fingerprint(&public_key);
        let nonce = random_nonce().unwrap();
        let signature = key.sign(&rng, &register_transcript(&fp, &nonce)).unwrap();

        verify_fingerprint(&fp, &public_key).unwrap();
        verify_registration(&public_key, &fp, &nonce, signature.as_ref()).unwrap();
    }

    #[test]
    fn rejects_a_claimed_fingerprint_that_is_not_the_key_hash() {
        let key = keypair();
        let public_key = key.public_key().as_ref().to_vec();
        let err = verify_fingerprint("dead:beef", &public_key).unwrap_err();
        assert!(matches!(err, AuthError::FingerprintMismatch));
    }

    #[test]
    fn rejects_a_signature_over_a_different_nonce() {
        let rng = SystemRandom::new();
        let key = keypair();
        let public_key = key.public_key().as_ref().to_vec();
        let fp = fingerprint(&public_key);
        let signature = key
            .sign(&rng, &register_transcript(&fp, &random_nonce().unwrap()))
            .unwrap();
        let other_nonce = random_nonce().unwrap();
        let err =
            verify_registration(&public_key, &fp, &other_nonce, signature.as_ref()).unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
    }

    #[test]
    fn rejects_a_signature_from_a_different_key() {
        let rng = SystemRandom::new();
        let honest = keypair();
        let attacker = keypair();
        let honest_public = honest.public_key().as_ref().to_vec();
        let fp = fingerprint(&honest_public);
        let nonce = random_nonce().unwrap();
        let signature = attacker
            .sign(&rng, &register_transcript(&fp, &nonce))
            .unwrap();
        let err = verify_registration(&honest_public, &fp, &nonce, signature.as_ref()).unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
    }

    #[test]
    fn transcript_is_domain_separated() {
        let transcript = register_transcript("aa:bb", b"nonce");
        assert!(transcript.starts_with(REGISTER_TRANSCRIPT_PREFIX));
    }
}
