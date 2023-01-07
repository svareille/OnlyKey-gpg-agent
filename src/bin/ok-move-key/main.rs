use std::{path::PathBuf, io};

use chrono::{DateTime, Local};
use clap::Parser;
use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::cert::prelude::ValidKeyAmalgamation;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{KeyParts, KeyRole};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{Curve};


/// Copy an existing private PGP key to an OnlyKey
#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// The path to an ASCII-armored private key or "-" if the key should be read from stdin.
    keyfile: PathBuf,
}

fn main() {
    let args = Args::parse();

    let key = if args.keyfile == PathBuf::from("-") {
        Cert::from_reader(io::stdin()).expect("couldn't read key from stdin")
    } else {
        Cert::from_file(&args.keyfile).unwrap_or_else(|e| panic!("couldn't read key from file {}: {}", args.keyfile.display(), e))
    };

    if !key.is_tsk() {
        eprintln!("The given key does not contain a secret key!");
        return;
    }

    let p = &StandardPolicy::new();
    let key = key.with_policy(p, None).expect("key is not valid");

    display_key(&key);
}

/// Display (println) the given key in a similar format as GPG does.
/// 
/// Output similar to `gpg -K --with-subkey-fingerprints`.
fn display_key(key: &ValidCert) {
    let primary = key.primary_key();
    let sec_str = if primary.has_secret() {"sec "} else {"sec#"};
    let creation_time: DateTime<Local> = primary.creation_time().into();
    // Primary key
    println!("{sec}  {type} {creation_time} {usage} {expiration}",
        sec=sec_str,
        type=algo_str(&primary),
        creation_time=creation_time.format("%Y-%m-%d"),
        usage=usage_str(&primary),
        expiration=expiration_str(&primary),
    );
    println!("      {fingerprint}", fingerprint = primary.fingerprint());
    // User Ids
    for uid in key.userids() {
        println!("uid          {}", uid.userid())
    }
    // Sub keys
    for subkey in key.keys().subkeys() {
        let ssb = if subkey.has_secret() {"ssb "} else {"ssb#"};
        let creation_time: DateTime<Local> = subkey.creation_time().into();
        println!("{ssb}  {type} {creation_time} {usage} {expiration}",
            type=algo_str(&subkey),
            creation_time=creation_time.format("%Y-%m-%d"),
            usage=usage_str(&subkey),
            expiration=expiration_str(&subkey),
        );
        println!("      {fingerprint}", fingerprint = subkey.fingerprint());
    }
}

fn algo_str<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> String
where P: 'a + KeyParts,
      R: 'a + KeyRole,
      R2: Copy,
{
    match key.mpis() {
        sequoia_openpgp::crypto::mpi::PublicKey::RSA { .. } => format!("rsa{}", key.mpis().bits().unwrap_or_default()),
        sequoia_openpgp::crypto::mpi::PublicKey::DSA { .. } => format!("dsa{}", key.mpis().bits().unwrap_or_default()),
        sequoia_openpgp::crypto::mpi::PublicKey::ElGamal { .. } => "elgamal".to_string(),
        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q: _ } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::ECDSA { curve, q: _ } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::ECDH { curve, q: _, hash: _, sym: _ } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::Unknown { mpis: _, rest: _ } => "unknown".to_string(),
        _ => "unknown".to_string(),
    }
}

fn curve_to_str(curve: &Curve) -> String {
    match curve {
        sequoia_openpgp::types::Curve::NistP256 => "nistp256".to_string(),
        sequoia_openpgp::types::Curve::NistP384 => "nistp384".to_string(),
        sequoia_openpgp::types::Curve::NistP521 => "nistp521".to_string(),
        sequoia_openpgp::types::Curve::BrainpoolP256 => "brainpoolp256".to_string(),
        sequoia_openpgp::types::Curve::BrainpoolP512 => "brainpoolp512".to_string(),
        sequoia_openpgp::types::Curve::Ed25519 => "ed25519".to_string(),
        sequoia_openpgp::types::Curve::Cv25519 => "cv25519".to_string(),
        sequoia_openpgp::types::Curve::Unknown(_) => "unknown".to_string(),
    }
}

fn usage_str<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> String 
where P: 'a + KeyParts,
      R: 'a + KeyRole,
      R2: Copy,
      ValidKeyAmalgamation<'a, P, R, R2>: ValidAmalgamation<'a, Key<P, R>>,
{
    let mut s = String::new();
        if key.for_storage_encryption() || key.for_transport_encryption() {
            s += "E";
        }
        if key.for_signing() {
            s += "S";
        }
        if key.for_authentication() {
            s += "A";
        }
        if key.for_certification() {
            s += "C";
        }
        if !s.is_empty() {
            s = format!("[{}]", s);
        }
        s
}

fn expiration_str<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> String 
where P: 'a + KeyParts,
      R: 'a + KeyRole,
      R2: Copy,
      ValidKeyAmalgamation<'a, P, R, R2>: ValidAmalgamation<'a, Key<P, R>>,
{
    match key.key_expiration_time() {
        None => String::new(),
        Some(time) => {
            let time: DateTime<Local> = time.into();
            format!("[expire: {}]", time.format("%Y-%m-%d"))
        }
    }
}