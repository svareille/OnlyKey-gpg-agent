use anyhow::{Result, bail, Context};
use chrono::{Utc, DateTime, Duration};
use ok_gpg_agent::{config::{DerivedKeyInfo, EccType, KeyInfo}, onlykey::OnlyKey};
use sequoia_openpgp::{Cert, packet::{UserID, Key, prelude::Key4, key::{PublicParts, PrimaryRole, SubordinateRole}, signature::SignatureBuilder}, Packet, crypto::{mpi::{PublicKey, MPI}, Signer}, types::{Curve, SignatureType, SymmetricAlgorithm, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, Features}, serialize::SerializeInto};
use crate::EccKind;

pub(crate) fn gen_key(identity: String, key_kind: EccKind, creation: DateTime<Utc>, validity: Duration) -> Result<String> {

    let onlykey = match OnlyKey::hid_connect().context("Could not connect to the OnlyKey")? {
        Some(ok) => ok,
        None =>  {
            eprintln!("No OnlyKey connected. Aborting.");
            bail!("No OnlyKey connected");
        },
    };

    let sign_key_info = KeyInfo::DerivedKey(DerivedKeyInfo{
        identity: identity.clone(),
        ecc_type: match key_kind {
            EccKind::Ed25519 => EccType::Ed25519,
            EccKind::Nist256 => EccType::Nist256P1,
            EccKind::Secp256 => EccType::Secp256K1,
        },
        keygrip: String::new(),
        validity: validity.num_days(),
        creation: creation.timestamp(),
    });
    let verifying_key = onlykey.pubkey(&sign_key_info).context("Could not get the verifying public key")?;

    let decrypt_key_info = KeyInfo::DerivedKey(DerivedKeyInfo{
        identity: identity.clone(),
        ecc_type: match key_kind {
            EccKind::Ed25519 => EccType::Cv25519,
            EccKind::Nist256 => EccType::Nist256P1,
            EccKind::Secp256 => EccType::Secp256K1,
        },
        keygrip: String::new(),
        validity: validity.num_days(),
        creation: creation.timestamp(),
    });
    
    let encryption_key = onlykey.pubkey(&decrypt_key_info).context("Could not get the encryption public key")?;

    // Generating a [Transferable Public Key](https://www.rfc-editor.org/rfc/rfc4880#section-11.1)

    let primary_key: Key<PublicParts, PrimaryRole> = Key::from(Key4::new(
        creation,
        match key_kind {
            EccKind::Ed25519 => PublicKeyAlgorithm::EdDSA,
            EccKind::Nist256 => PublicKeyAlgorithm::ECDSA,
            EccKind::Secp256 => PublicKeyAlgorithm::ECDSA,
        },
        match key_kind {
            EccKind::Ed25519 => PublicKey::EdDSA { curve: Curve::Ed25519, q: MPI::new_compressed_point(&verifying_key) },
            EccKind::Nist256 => PublicKey::ECDSA { curve: Curve::NistP256, q: MPI::new_point(&verifying_key[..32], &verifying_key[32..], 256) },
            EccKind::Secp256 => unimplemented!("Secp256k1 curve is currently not supported by sequoia"),
        }).context("Failed to generate primary key")?);
    
    let mut ok_signer = OnlyKeySigner::new(primary_key.clone(), onlykey, sign_key_info);

    let mut public_key = Cert::try_from(Packet::PublicKey(primary_key.clone())).context("Failed to generate certificate from primary key")?;

    let user_id = UserID::from(identity);
    let uid_sig_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_signature_creation_time(creation)
        .and_then(|b|b.set_key_validity_period(validity.to_std().unwrap()))
        .and_then(|b|b.set_key_flags(KeyFlags::empty().set_certification().set_signing()))
        .and_then(|b|b.set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES192,
            SymmetricAlgorithm::AES128,
            SymmetricAlgorithm::TripleDES,
        ]))
        .and_then(|b|b.set_preferred_hash_algorithms(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA224,
            HashAlgorithm::SHA1,
        ]))
        .and_then(|b|b.set_preferred_compression_algorithms(vec![
            CompressionAlgorithm::Zlib,
            CompressionAlgorithm::BZip2,
            CompressionAlgorithm::Zip,
        ]))
        .and_then(|b|b.set_issuer_fingerprint(primary_key.fingerprint()))
        .and_then(|b|b.set_features(Features::empty().set_aead().set_mdc()))
        .context("Failed to create User ID's signature Builder")?;

    let uid_signature = uid_sig_builder.sign_userid_binding(&mut ok_signer, None, &user_id).context("Failed to create the User ID's signature")?;

    public_key = public_key.insert_packets(user_id).context("Failed to add the User ID to the cert")?;
    public_key = public_key.insert_packets(uid_signature).context("Failed to add the User ID's signature to the cert")?;


    let subkey: Key<PublicParts, SubordinateRole> = Key::from(Key4::new(
        creation,
        PublicKeyAlgorithm::ECDH,
        match key_kind {
            EccKind::Ed25519 => PublicKey::ECDH { curve: Curve::Ed25519, q: MPI::new_compressed_point(&encryption_key), hash: HashAlgorithm::SHA512, sym: SymmetricAlgorithm::AES256 },
            EccKind::Nist256 => PublicKey::ECDH { curve: Curve::NistP256, q: MPI::new_point(&encryption_key[..32], &encryption_key[32..], 256), hash: HashAlgorithm::SHA512, sym: SymmetricAlgorithm::AES256 },
            EccKind::Secp256 => unimplemented!("Secp256k1 curve is currently not supported by sequoia"),
        }).context("Failed to generate subordinate key")?);

    let subkey_sig_builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_signature_creation_time(creation)
        .and_then(|b|b.set_key_validity_period(validity.to_std().unwrap()))
        .and_then(|b|b.set_key_flags(KeyFlags::empty().set_storage_encryption().set_transport_encryption()))
        .and_then(|b|b.set_issuer_fingerprint(primary_key.fingerprint()))
        .context("Failed to create the subkey's signature Builder")?;
    
    let subkey_signature = subkey_sig_builder.sign_subkey_binding(&mut ok_signer, None, &subkey).context("Failed to create the subkey's signature")?;

    public_key = public_key.insert_packets(subkey).context("Failed to add the subkey to the cert")?;
    public_key = public_key.insert_packets(subkey_signature).context("Failed to add the subkey's signature to the cert")?;
    
    let armored = String::from_utf8(public_key.armored().to_vec().unwrap()).context("Failed to armor the cert")?;
    Ok(armored)
}

struct OnlyKeySigner {
    pubkey: Key<PublicParts, sequoia_openpgp::packet::key::PrimaryRole>,
    onlykey: OnlyKey,
    key_info: KeyInfo,
}

impl OnlyKeySigner {
    fn new(pubkey: Key<PublicParts, sequoia_openpgp::packet::key::PrimaryRole>, onlykey: OnlyKey, key_info: KeyInfo) -> Self {
        OnlyKeySigner { pubkey, onlykey, key_info }
    }
}

impl Signer for OnlyKeySigner {
    fn public(&self) -> &Key<sequoia_openpgp::packet::key::PublicParts, sequoia_openpgp::packet::key::UnspecifiedRole> {
        self.pubkey.role_as_unspecified()
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> sequoia_openpgp::Result<sequoia_openpgp::crypto::mpi::Signature> {
        println!("Signature hash algo: {:?}", hash_algo);
        let (b1, b2, b3) = OnlyKey::compute_challenge(&OnlyKey::data_to_send(digest, &self.key_info));
        println!("Touch your OnlyKey or enter the following 3 digit challenge code to authorize signing:\n{} {} {}", b1, b2, b3);

        let signature = self.onlykey.sign(digest, &self.key_info)?;
        match self.key_info.r#type() {
            ok_gpg_agent::config::KeyType::Rsa(_) => unreachable!(),
            ok_gpg_agent::config::KeyType::Ecc(ecc) => match ecc {
                EccType::Unknown => unreachable!(),
                EccType::Ed25519 => Ok(sequoia_openpgp::crypto::mpi::Signature::EdDSA { r: MPI::new(&signature[0..32]), s: MPI::new(&signature[32..64]) }),
                EccType::Cv25519 => unreachable!(),
                EccType::Nist256P1 => Ok(sequoia_openpgp::crypto::mpi::Signature::ECDSA { r: MPI::new(&signature[0..32]), s: MPI::new(&signature[32..64]) }),
                EccType::Secp256K1 => Ok(sequoia_openpgp::crypto::mpi::Signature::ECDSA { r: MPI::new(&signature[0..32]), s: MPI::new(&signature[32..64]) }),
            },
        }
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256, HashAlgorithm::SHA512,]
    }
}