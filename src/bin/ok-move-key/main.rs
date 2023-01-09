use std::{path::PathBuf, io};

use chrono::{DateTime, Local};
use clap::Parser;
use ok_gpg_agent::onlykey::OnlyKey;
use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::cert::prelude::ValidKeyAmalgamation;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{KeyParts, KeyRole};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{Curve};

use text_io::read;

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

    println!();
    display_key(&key);
    println!();

    let mut selected_keys: Vec<usize> = Vec::new();

    while selected_keys.is_empty() {
        print!("Please select witch key(s) to copy on the OnlyKey: ");
        let key_numbers: String = read_line!();
        selected_keys = key_numbers.split_whitespace().filter_map(|s| s.parse().ok()).collect();
        
        // Check if the selected keys are valid
        let mut good_selection = true;
        for &selected in &selected_keys {
            if let Some(k) = key.keys().nth(selected) {
                if !has_secret(&k) {
                    println!("Wrong selection: the key n°{selected} does not contain any secret. Please choose again.");
                    good_selection = false;
                    break;
                }
            } else {
                println!("Wrong selection: there is no key n°{selected}. Please choose again.");
                good_selection = false;
                break;
            }
        }

        if !good_selection {
            selected_keys.clear()
        } else {
            // Perform a few verifications

            selected_keys.retain(|&selected| {
                if let Some(k) = key.keys().nth(selected) {
                    if k.alive().is_err() {
                        print!("The key n°{selected}: \"{}\" is expired. Do you really want to copy it (y/n)? ", key_info_str(&k, selected == 0));
                        matches!(read!(), 'y')
                    } else {
                        true
                    }
                } else {
                    false
                }
            });

            if !good_selection {
                selected_keys.clear();
            } else {            
                print!("You chose the key(s) {selected_keys:?}. Is this correct (y/n)? ");
                if let 'y' = read!() {
                    break;
                } else {
                    selected_keys.clear();
                }
            }
        }
    }
}

/// Display (println) the given key in a similar format as GPG does.
/// 
/// Output similar to `gpg -K --with-subkey-fingerprints`.
fn display_key(key: &ValidCert) {
    let primary = key.primary_key();

    // Primary key
    println!("0: {}", key_info_str(&primary, true));
    println!("         {fingerprint}", fingerprint = primary.fingerprint());
    // User Ids
    for uid in key.userids() {
        println!("uid          {}", uid.userid())
    }
    // Sub keys
    let mut i = 1;
    for subkey in key.keys().subkeys() {
        println!("{i}: {}", key_info_str(&subkey, false));
        println!("         {fingerprint}", fingerprint = subkey.fingerprint());
        i += 1;
    }
}

fn key_info_str<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>, primary: bool) -> String
where P: 'a + KeyParts,
      R: 'a + KeyRole,
      R2: Copy,
      ValidKeyAmalgamation<'a, P, R, R2>: ValidAmalgamation<'a, Key<P, R>>,
{
    
    let sec = if primary { if has_secret(key) {"sec "} else {"sec#"} }
        else if has_secret(key) {"ssb "} else {"ssb#"};
    let creation_time: DateTime<Local> = key.creation_time().into();
    format!("{sec}  {type} {creation_time} {usage} {expiration}",
        type=algo_str(key),
        creation_time=creation_time.format("%Y-%m-%d"),
        usage=usage_str(key),
        expiration=expiration_str(key),
    )
}

fn has_secret<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> bool
where P: 'a + KeyParts,
      R: 'a + KeyRole,
      R2: Copy,
{
    match key.key().optional_secret() {
        None => false,
        Some(sequoia_openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) => {
            !matches!(encrypted.s2k(), sequoia_openpgp::crypto::S2K::Private { tag: 101, parameters: _ }) // GnuPG extension for offline master key
        },
        _ => true,
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

#[cfg(windows)]
#[macro_export]
macro_rules! read_line {
    (  ) => {
        {
            read!("{}\r\n")
        }
    };
}

#[cfg(unix)]
#[macro_export]
macro_rules! read_line {
    ( $( $x:expr ),* ) => {
        {
            read!("{}\n")
        }
    };
}