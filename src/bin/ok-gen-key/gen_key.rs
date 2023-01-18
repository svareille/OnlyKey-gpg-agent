use std::fmt::Debug;

use base64::{engine::general_purpose, Engine};
use chrono::{Utc, DateTime, Duration};
use ok_gpg_agent::{config::{DerivedKeyInfo, EccType, KeyInfo}, onlykey::OnlyKey};
use sha1::Sha1;
use sha2::{Digest, Sha512};
use crate::{EccKind};

pub(crate) fn gen_key(identity: String, key_kind: EccKind, creation: DateTime<Utc>, validity: Duration) -> Result<String, ()> {

    let onlykey = match OnlyKey::hid_connect().unwrap() {
        Some(ok) => ok,
        None =>  {
            println!("No OnlyKey connected. Aborting.");
            return Err(());
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
    });
    let verifying_key = onlykey.pubkey(&sign_key_info).unwrap();

    let decrypt_key_info = KeyInfo::DerivedKey(DerivedKeyInfo{
        identity: identity.clone(),
        ecc_type: match key_kind {
            EccKind::Ed25519 => EccType::Cv25519,
            EccKind::Nist256 => EccType::Nist256P1,
            EccKind::Secp256 => EccType::Secp256K1,
        },
        keygrip: String::new(),
    });
    
    let encryption_key = onlykey.pubkey(&decrypt_key_info).unwrap();

    // Generating a [Transferable Public Key](https://www.rfc-editor.org/rfc/rfc4880#section-11.1)

    let signature_algo = match key_kind {
        EccKind::Ed25519 => PublicKeyAlgorithm::EDDSA,
        EccKind::Nist256 => PublicKeyAlgorithm::ECDSA,
        EccKind::Secp256 => PublicKeyAlgorithm::ECDSA,
    };

    let encryption_algo = PublicKeyAlgorithm::ECDH;

    let pubkey_body = gen_public_key_body(
        signature_algo,
        key_kind,
        match key_kind {
            EccKind::Ed25519 => Mpi::new_from_ed25519(&verifying_key),
            EccKind::Nist256 => Mpi::new_from_nistp(&verifying_key),
            EccKind::Secp256 => Mpi::new_from_secp(&verifying_key),
        },
        creation
    );
    let primary_key_packet = gen_packet(PacketTag::PublicKey, &pubkey_body);

    let user_id_body = gen_user_id_body(&identity);
    let primary_user_id_packet = gen_packet(PacketTag::UserId, &user_id_body);

    let user_id_signature_body = gen_user_id_signature_body(&pubkey_body, &user_id_body, signature_algo, creation, validity, &onlykey, &sign_key_info);
    let user_id_signature_packet = gen_packet(PacketTag::Signature, &user_id_signature_body);

    let subkey_body = gen_public_key_body(
        encryption_algo,
        key_kind,
        match key_kind {
            EccKind::Ed25519 => Mpi::new_from_ed25519(&encryption_key),
            EccKind::Nist256 => Mpi::new_from_nistp(&encryption_key),
            EccKind::Secp256 => Mpi::new_from_secp(&encryption_key),
        },
        creation
    );
    let subkey_packet = gen_packet(PacketTag::PublicSubkey, &subkey_body);

    let subkey_signature_body = gen_subkey_signature_body(&pubkey_body, &subkey_body,signature_algo, creation, validity, &onlykey, &sign_key_info);
    let subkey_signature_packet = gen_packet(PacketTag::Signature, &subkey_signature_body);

    let mut transferable_key = primary_key_packet;
    transferable_key.extend(primary_user_id_packet);
    transferable_key.extend(user_id_signature_packet);
    transferable_key.extend(subkey_packet);
    transferable_key.extend(subkey_signature_packet);

    let mut armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n".to_owned();
    armored += "\n";
    armored += &general_purpose::STANDARD.encode(&transferable_key).as_bytes().chunks(76).map(|chunk| String::from_utf8(chunk.to_vec()).unwrap() + "\n").collect::<String>();
    let crc = crc24::hash_raw(&transferable_key);
    armored += "=";
    general_purpose::STANDARD.encode_string(&crc.to_be_bytes()[1..], &mut armored);
    armored += "\n";
    armored += "-----END PGP PUBLIC KEY BLOCK-----";

    Ok(armored)
}

#[derive(Copy, Clone)]
enum PacketTag {
    Signature,
    PublicKey,
    UserId,
    PublicSubkey,
}

impl PacketTag {
    fn to_int(self) -> u8 {
        match self {
            PacketTag::Signature => 2,
            PacketTag::PublicKey => 6,
            PacketTag::UserId => 13,
            PacketTag::PublicSubkey => 14,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy)]
enum PublicKeyAlgorithm {
    ECDH,  // Encryption
    ECDSA, // Signature with NIST-P256 and SECP256
    EDDSA, // Signature with Ed25519
}

impl PublicKeyAlgorithm {
    fn as_int(&self) -> u8 {
        match &self {
            PublicKeyAlgorithm::ECDH => 18,
            PublicKeyAlgorithm::ECDSA => 19,
            PublicKeyAlgorithm::EDDSA => 22,
        }
    }
}

struct Mpi {
    value: Vec<u8>,
}

impl Mpi {
    fn new_from_ed25519(value: &[u8]) -> Mpi {
        let mut val = vec![0x40];
        val.extend_from_slice(value);
        Mpi { value: val }
    }
    fn new_from_nistp(value: &[u8]) -> Mpi {
        let mut val = vec![0x04];
        val.extend_from_slice(value);
        Mpi { value: val }
    }
    fn new_from_secp(value: &[u8]) -> Mpi {
        let mut val = vec![0x04];
        val.extend_from_slice(value);
        Mpi { value: val }
    }

    fn len(&self) -> u16 {
        for (index, byte) in self.value.iter().enumerate() {
            if *byte != 0 {
                if *byte >= 0b1000_0000 {
                    return ((self.value.len() - index)*8) as u16;
                } else if *byte >= 0b0100_0000 {
                    return ((self.value.len() - index)*8 - 1) as u16;
                } else if *byte >= 0b0010_0000 {
                    return ((self.value.len() - index)*8 - 2) as u16;
                } else if *byte >= 0b0001_0000 {
                    return ((self.value.len() - index)*8 - 3) as u16;
                } else if *byte >= 0b0000_1000 {
                    return ((self.value.len() - index)*8 - 4) as u16;
                } else if *byte >= 0b0000_0100 {
                    return ((self.value.len() - index)*8 - 5) as u16;
                } else if *byte >= 0b0000_0010 {
                    return ((self.value.len() - index)*8 - 6) as u16;
                }
                return ((self.value.len() - index)*8 - 7) as u16;
            }
        }
        0
    }

    fn to_vec(&self) -> Vec<u8> {

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.len().to_be_bytes());
        bytes.extend_from_slice(self.shorten_value());
        bytes
    }

    fn shorten_value(&self) -> &[u8] {
        for (index, byte) in self.value.iter().enumerate() {
            if *byte != 0 {
                return &self.value[index..];
            }
        }
        &[0]
    }
}

impl Debug for Mpi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mpi").field("len", &self.len()).field("value", &self.shorten_value()).finish()
    }
}

#[allow(dead_code)]
enum KeyFlags {
    Certification,
    Signature,
    EncryptionComm,
    EncryptionStor,
    Shared,
    Authentication,
    Group,
}

impl KeyFlags {
    fn to_int(&self) -> u8 {
        match self {
            KeyFlags::Certification => 0x01,
            KeyFlags::Signature => 0x02,
            KeyFlags::EncryptionComm => 0x04,
            KeyFlags::EncryptionStor => 0x08,
            KeyFlags::Shared => 0x10,
            KeyFlags::Authentication => 0x20,
            KeyFlags::Group => 0x80,
        }
    }
}

#[allow(dead_code, clippy::upper_case_acronyms)]
enum SymmetricAlgorithm {
    Plaintext,
    IDEA,
    TripleDES,
    CAST5,
    Blowfish,
    AES128,
    AES192,
    AES256,
    TwoFish,
}
impl SymmetricAlgorithm {
    fn to_int(&self) -> u8 {
        match self {
            SymmetricAlgorithm::Plaintext => 0,
            SymmetricAlgorithm::IDEA => 1,
            SymmetricAlgorithm::TripleDES => 2,
            SymmetricAlgorithm::CAST5 => 3,
            SymmetricAlgorithm::Blowfish => 4,
            SymmetricAlgorithm::AES128 => 7,
            SymmetricAlgorithm::AES192 => 8,
            SymmetricAlgorithm::AES256 => 9,
            SymmetricAlgorithm::TwoFish => 10,
        }
    }
}

#[allow(dead_code)]
enum HashAlgorithm {
    MD5,
    SHA1,
    RIPEMD160,
    SHA256,
    SHA384,
    SHA512,
    SHA224,
}
impl HashAlgorithm {
    fn to_int(&self) -> u8 {
        match self {
            HashAlgorithm::MD5 => 1,
            HashAlgorithm::SHA1 => 2,
            HashAlgorithm::RIPEMD160 => 3,
            HashAlgorithm::SHA256 => 8,
            HashAlgorithm::SHA384 => 9,
            HashAlgorithm::SHA512 => 10,
            HashAlgorithm::SHA224 => 11,
        }
    }
}

#[allow(dead_code, clippy::upper_case_acronyms)]
enum CompressionAlgorithm {
    Uncompressed,
    ZIP,
    ZLIB,
    BZip2,
}
impl CompressionAlgorithm {
    fn to_int(&self) -> u8 {
        match self {
            CompressionAlgorithm::Uncompressed => 0,
            CompressionAlgorithm::ZIP => 1,
            CompressionAlgorithm::ZLIB => 2,
            CompressionAlgorithm::BZip2 => 3,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
enum Features {
    ModificationDection,
    AEAD,
    V5,
}
impl Features {
    fn to_int(&self) -> u8 {
        match self {
            Features::ModificationDection => 0x01,
            Features::AEAD => 0x02,
            Features::V5 => 0x04,
        }
    }
}

enum SignatureSubpacket {
    SignatureCreationTime(DateTime<Utc>),
    KeyFlags(Vec<KeyFlags>),
    PreferedSymmetricAlgos(Vec<SymmetricAlgorithm>),
    PreferedHashAlgos(Vec<HashAlgorithm>),
    PreferedZipAlgos(Vec<CompressionAlgorithm>),
    Expiration(Duration),
    Issuer(Vec<u8>),
    IssuerFingerprint(Vec<u8>),
    Features(Vec<Features>),
}

impl SignatureSubpacket {
    fn into_vec(self) -> Vec<u8> {
        let p = match self {
            SignatureSubpacket::SignatureCreationTime(tm) => {
                let mut p = vec![2];
                p.extend_from_slice(&(tm.timestamp() as u32).to_be_bytes());
                p
            },
            SignatureSubpacket::KeyFlags(flags) => {
                let mut p = vec![27];
                p.extend_from_slice(&flags.into_iter().map(|f| f.to_int()).reduce(|a, b| a | b).unwrap_or_default().to_be_bytes());
                p
            },
            SignatureSubpacket::PreferedSymmetricAlgos(algos) => {
                let mut p = vec![11];
                p.append(&mut algos.into_iter().map(|f| f.to_int()).collect());
                p
            },
            SignatureSubpacket::PreferedHashAlgos(algos) => {
                let mut p = vec![21];
                p.append(&mut algos.into_iter().map(|f| f.to_int()).collect());
                p
            },
            SignatureSubpacket::PreferedZipAlgos(algos) => {
                let mut p = vec![22];
                p.append(&mut algos.into_iter().map(|f| f.to_int()).collect());
                p
            },
            SignatureSubpacket::Expiration(dur) => {
                let mut p = vec![9];
                p.extend_from_slice(&(dur.num_seconds() as u32).to_be_bytes());
                p
            },
            SignatureSubpacket::Issuer(mut id) => {
                let mut p = vec![16];
                p.append(&mut id);
                p
            },
            SignatureSubpacket::IssuerFingerprint(mut fpr) => {
                let mut p = vec![33, 4];
                p.append(&mut fpr);
                p
            },
            SignatureSubpacket::Features(features) => {
                let mut p = vec![30];
                p.extend_from_slice(&features.into_iter().map(|f| f.to_int()).reduce(|a, b| a | b).unwrap_or_default().to_be_bytes());
                p
            },
            
        };
        let mut packet = encode_len(p.len());
        packet.extend(p);
        packet
    }
}

/// Generate a packet header in new format.
/// https://www.rfc-editor.org/rfc/rfc4880#section-4.2
/// 
/// Note: No endianness pitfall.
fn gen_packet(tag: PacketTag, body: &[u8]) -> Vec<u8> {
    let tag = 0b1100_0000 | tag.to_int() ;
    let mut packet = vec![tag];
    packet.append(&mut encode_len(body.len()));
    packet.extend_from_slice(body);
    packet
}

/// Encode the length.
/// 
/// Note: No endianness pitfall.
fn encode_len(len: usize) -> Vec<u8> {
    match len {
        0..=191 => vec![len as u8],
        192..=8383 => {
            // len = ((1st_octet - 192) << 8) + (2nd_octet) + 192
            let len = len as u16 - 192;
            vec![((len >> 8)+192) as u8, len as u8]
        },
        8384..=0xffffffff => {
            vec![255, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]
        },
        n => unimplemented!("Encoding packets of length {n} > 0xffffffff is not supported"),
    }
}

/// Generate the body of a public key packet.
/// Can be used for primary key and subkey.
/// 
/// https://www.rfc-editor.org/rfc/rfc4880#section-5.5.2
fn gen_public_key_body(algo: PublicKeyAlgorithm, key_kind: EccKind, key: Mpi, creation: DateTime<Utc>) -> Vec<u8> {
    let mut packet = vec![4];
    let created = creation.timestamp() as u32;
    packet.extend_from_slice(&created.to_be_bytes());
    packet.push(algo.as_int());
    match algo {
        PublicKeyAlgorithm::ECDH => {
            let mut curve_oid: Vec<u8> =  match key_kind {
                EccKind::Ed25519 => vec![10, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],//Curve25519
                EccKind::Nist256 => vec![8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
                EccKind::Secp256 => todo!(),
            };
            packet.append(&mut curve_oid);
            match key_kind {
                EccKind::Ed25519 => {
                    packet.append(&mut key.to_vec());
                },
                EccKind::Nist256 => todo!(),
                EccKind::Secp256 => todo!(),
            }
            
            // KDF
            packet.append(&mut vec![3, // length
                1, // Reserved
                8, // SHA256
                7, // AES128
                ]);
        },
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::EDDSA => {
            let mut curve_oid: Vec<u8> =  match key_kind {
                EccKind::Ed25519 => vec![9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],//ed25519
                EccKind::Nist256 => vec![8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
                EccKind::Secp256 => todo!(),
            };
            packet.append(&mut curve_oid);
            packet.append(&mut key.to_vec());
        }
    }

    packet
}

fn gen_user_id_body(identity: &str) -> Vec<u8> {
    identity.as_bytes().to_vec()
}

/// https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3
fn gen_user_id_signature_body(key_packet_body: &[u8], user_id_body: &[u8], algo: PublicKeyAlgorithm, creation: DateTime<Utc>, expire: Duration, onlykey: &OnlyKey, sign_key: &KeyInfo) -> Vec<u8> {
    let mut packet = vec![
        4, // Version
        0x13, // Positive certification
        algo.as_int(),
        HashAlgorithm::SHA512.to_int(),
        ];
    
    let hashed_subpackets: Vec<SignatureSubpacket> = vec![
        SignatureSubpacket::SignatureCreationTime(creation),
        SignatureSubpacket::KeyFlags(vec![
            KeyFlags::Signature,
            KeyFlags::Certification,
        ]),
        SignatureSubpacket::PreferedSymmetricAlgos(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES192,
            SymmetricAlgorithm::AES128,
            SymmetricAlgorithm::TripleDES,
        ]),
        SignatureSubpacket::PreferedHashAlgos(vec![
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA224,
            HashAlgorithm::SHA1,
        ]),
        SignatureSubpacket::PreferedZipAlgos(vec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::BZip2,
            CompressionAlgorithm::ZIP,
        ]),
        SignatureSubpacket::Expiration(expire),
        SignatureSubpacket::IssuerFingerprint(fingerprint(key_packet_body)),
        SignatureSubpacket::Features(vec![
            Features::ModificationDection,
            Features::AEAD,
            Features::V5,
        ])
    ];
    let mut hashed_subpackets: Vec<u8> = hashed_subpackets.into_iter().flat_map(|p|p.into_vec()).collect();

    packet.extend_from_slice(&(hashed_subpackets.len() as u16).to_be_bytes());
    packet.append(&mut hashed_subpackets);

    let non_hashed_subpackets = vec![
        SignatureSubpacket::Issuer(key_id(key_packet_body)),
    ];
    let mut non_hashed_subpackets: Vec<u8> = non_hashed_subpackets.into_iter().flat_map(|p|p.into_vec()).collect();

    let hash = Sha512::new()
        // The key
        .chain_update(&[0x99,])
        .chain_update((key_packet_body.len() as u16).to_be_bytes())
        .chain_update(key_packet_body)
        // The User ID
        .chain_update(&[0xb4])
        .chain_update((user_id_body.len() as u32).to_be_bytes())
        .chain_update(user_id_body)
        // The signature packet
        .chain_update(&packet)
        // Final trailer
        .chain_update(&[0x04, 0xff])
        .chain_update((packet.len() as u32).to_be_bytes())
        .finalize();

    packet.extend_from_slice(&(non_hashed_subpackets.len() as u16).to_be_bytes());
    packet.append(&mut non_hashed_subpackets);

    packet.extend_from_slice(&hash[0..2]);

    let (b1, b2, b3) = OnlyKey::compute_challenge(&OnlyKey::data_to_send(&hash, sign_key));
    println!("Touch your OnlyKey or enter the following 3 digit challenge code to authorize signing:\n{} {} {}", b1, b2, b3);

    let res = onlykey.sign(&hash, sign_key).unwrap();
    
    let r = res[..32].to_vec();
    let s = res[32..].to_vec();

    let r = Mpi{value: r};
    let s = Mpi{value: s};

    //println!("r={:x?}\ns={:x?}", r, s);

    packet.extend(r.to_vec());
    packet.extend(s.to_vec());

    packet
}

fn gen_subkey_signature_body(key_packet_body: &[u8], subkey_body: &[u8], algo: PublicKeyAlgorithm, creation: DateTime<Utc>, expire: Duration, onlykey: &OnlyKey, sign_key: &KeyInfo) -> Vec<u8> {
    let mut packet = vec![
        4, // Version
        0x18, // Subkey Binding Signature
        algo.as_int(),
        HashAlgorithm::SHA512.to_int(),
        ];

    let hashed_subpackets: Vec<SignatureSubpacket> = vec![
        SignatureSubpacket::SignatureCreationTime(creation),
        SignatureSubpacket::KeyFlags(vec![
            KeyFlags::EncryptionComm,
            KeyFlags::EncryptionStor,
        ]),
        SignatureSubpacket::Expiration(expire),
        SignatureSubpacket::IssuerFingerprint(fingerprint(key_packet_body)),
    ];
    let mut hashed_subpackets: Vec<u8> = hashed_subpackets.into_iter().flat_map(|p|p.into_vec()).collect();

    let non_hashed_subpackets = vec![
        SignatureSubpacket::Issuer(key_id(key_packet_body)),
    ];
    let mut non_hashed_subpackets: Vec<u8> = non_hashed_subpackets.into_iter().flat_map(|p|p.into_vec()).collect();

    packet.extend_from_slice(&(hashed_subpackets.len() as u16).to_be_bytes());
    packet.append(&mut hashed_subpackets);

    let hash = Sha512::new()
        // The key
        .chain_update(&[0x99,])
        .chain_update((key_packet_body.len() as u16).to_be_bytes())
        .chain_update(key_packet_body)
        // The Subkey
        .chain_update(&[0x99])
        .chain_update((subkey_body.len() as u16).to_be_bytes())
        .chain_update(subkey_body)
        // The signature packet
        .chain_update(&packet)
        // Final trailer
        .chain_update(&[0x04, 0xff])
        .chain_update((packet.len() as u32).to_be_bytes())
        .finalize();

    packet.extend_from_slice(&(non_hashed_subpackets.len() as u16).to_be_bytes());
    packet.append(&mut non_hashed_subpackets);

    packet.extend_from_slice(&hash[0..2]);

    let (b1, b2, b3) = OnlyKey::compute_challenge(&OnlyKey::data_to_send(&hash, sign_key));
    println!("Touch your OnlyKey or enter the following 3 digit challenge code to authorize signing:\n{} {} {}", b1, b2, b3);

    let res = onlykey.sign(&hash, sign_key).unwrap();

    let r = Mpi{value: res[..32].to_vec()};
    let s = Mpi{value: res[32..].to_vec()};

    packet.extend(r.to_vec());
    packet.extend(s.to_vec());

    packet
}

fn fingerprint(key_body: &[u8]) -> Vec<u8> {

    let fpr = Sha1::new()
        .chain_update(&[0x99,])
        .chain_update((key_body.len() as u16).to_be_bytes())
        .chain_update(key_body)
        .finalize();
    
    fpr.to_vec()
}

fn key_id(key_body: &[u8]) -> Vec<u8> {
    let fpr = fingerprint(key_body);
    fpr[fpr.len()-8..].to_vec()
}