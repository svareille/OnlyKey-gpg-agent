use std::{io, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Local};
use clap::Parser;
use ok_gpg_agent::config::KeyType;
use ok_gpg_agent::onlykey::{KeyRole, OnlyKey};
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::cert::prelude::ValidKeyAmalgamation;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::crypto::mpi::SecretKeyMaterial;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::Curve;
use sequoia_openpgp::Cert;

use text_io::read;

/// Copy an existing private PGP key to an OnlyKey
#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// The path to an ASCII-armored private key or "-" if the key should be read from stdin.
    /// Required unless --list-slots is present.
    #[arg(required_unless_present_any=["list_slots"])]
    keyfile: Option<PathBuf>,

    /// List empty slots and exit.
    #[arg(short = 's', long, conflicts_with = "keyfile")]
    list_slots: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_slots {
        let onlykey = match OnlyKey::hid_connect().context("Could not connect to the OnlyKey:")? {
            Some(ok) => ok,
            None => {
                bail!("No OnlyKey connected");
            }
        };
        let empty_slots = onlykey
            .get_empty_key_slots()
            .context("Could not get the empty slots")?;

        println!("Empty slots: {:?}", empty_slots);
        return Ok(());
    }

    // From now we require keyfile to be set
    if args.keyfile.is_none() {
        bail!("The keyfile argument must be present");
    }

    let keyfile = args.keyfile.unwrap();

    let key = if keyfile == PathBuf::from("-") {
        Cert::from_reader(io::stdin()).context("Couldn't read key from stdin")?
    } else {
        Cert::from_file(&keyfile)
            .with_context(|| format!("Couldn't read key from file {}", keyfile.display()))?
    };

    if !key.is_tsk() {
        bail!("The given key does not contain a secret key!");
    }

    let p = &StandardPolicy::new();
    let key = key.with_policy(p, None).context("Key is not valid")?;

    println!();
    display_key(&key);
    println!();

    let mut selected_keys: Vec<usize> = Vec::new();

    while selected_keys.is_empty() {
        print!("Please select witch key(s) to copy on the OnlyKey: ");
        let key_numbers: String = read_line!();
        selected_keys = key_numbers
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();

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

    // The selection have been approved
    // Begin interaction with OnlyKey

    let onlykey = match OnlyKey::hid_connect().context("Could not connect to the OnlyKey")? {
        Some(ok) => ok,
        None => {
            bail!("No OnlyKey connected");
        }
    };

    println!(
        "Asking the connected OnlyKey for empty slots...
Make sure your key is not yet in config mode or else the connection will fail."
    );

    let mut empty_slots = onlykey
        .get_empty_key_slots()
        .context("Could not get the empty slots")?;

    // Hold the key, the sot in which the key will be transferred and a boolean indicating if the key is the primary key
    let mut keys_slots = Vec::new();

    for &selected in &selected_keys {
        let key_to_move = key.keys().nth(selected).unwrap();
        match key_to_move.mpis() {
            sequoia_openpgp::crypto::mpi::PublicKey::RSA { .. } => {
                match empty_slots
                    .iter()
                    .position(|slot| matches!(slot.r#type(), KeyType::Rsa(_)))
                {
                    Some(index) => {
                        let slot = empty_slots.remove(index);
                        keys_slots.push((selected, slot, selected == 0));
                    }
                    None => {
                        bail!("There is no empty slot for an RSA key");
                    }
                }
            }
            sequoia_openpgp::crypto::mpi::PublicKey::DSA { .. }
            | sequoia_openpgp::crypto::mpi::PublicKey::ElGamal { .. } => {
                bail!(
                    "Key type not supported: {}",
                    key_info_str(&key_to_move, selected == 0)
                );
            }
            sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q: _ }
            | sequoia_openpgp::crypto::mpi::PublicKey::ECDSA { curve, q: _ }
            | sequoia_openpgp::crypto::mpi::PublicKey::ECDH {
                curve,
                q: _,
                hash: _,
                sym: _,
            } => match curve {
                Curve::NistP256 | Curve::Ed25519 | Curve::Cv25519 => {
                    match empty_slots
                        .iter()
                        .position(|slot| matches!(slot.r#type(), KeyType::Ecc(_)))
                    {
                        Some(index) => {
                            let slot = empty_slots.remove(index);
                            keys_slots.push((selected, slot, selected == 0));
                        }
                        None => {
                            bail!("There is no empty slot for an ECC key");
                        }
                    }
                }
                Curve::NistP384
                | Curve::NistP521
                | Curve::BrainpoolP256
                | Curve::BrainpoolP512
                | Curve::Unknown(_) => {
                    bail!(
                        "Key type not supported: {}",
                        key_info_str(&key_to_move, selected == 0)
                    );
                }
            },
            _ => {
                bail!(
                    "Unknown key type: {}",
                    key_info_str(&key_to_move, selected == 0)
                );
            }
        }
    }

    // We have a slot for each key, proceed with secret extraction and writing

    println!("The selected keys will be transferred as follow:");
    for (index, slot, primary) in &keys_slots {
        println!(
            "Key \"{}\" => slot {}",
            key_info_str(&key.keys().nth(*index).unwrap(), *primary),
            slot
        );
    }

    print!(
        "Please put your key in config mode by holding the '6' button for 5 seconds or more.
Press 'Enter' when you're ready to continue."
    );
    let _: String = read_line!();

    let mut password = if keys_slots
        .iter()
        .any(|(index, _, _)| !key.keys().nth(*index).unwrap().has_unencrypted_secret())
    {
        rpassword::prompt_password("Please enter your key's password: ").unwrap()
    } else {
        String::new()
    };

    for (index, slot, primary) in &keys_slots {
        let key = key.keys().nth(*index).unwrap();
        let component = key.component();
        let parts = component
            .parts_as_secret()
            .context("Could not get secrets from key")?
            .clone();
        let decrypted_parts = {
            let mut decrypted = parts.clone().decrypt_secret(&password.clone().into());
            while decrypted.is_err() {
                println!("Error is: {:?}", decrypted);
                password = rpassword::prompt_password(
                    "Wrong password. Please re-enter your key's password: ",
                )
                .unwrap();
                decrypted = parts.clone().decrypt_secret(&password.clone().into());
            }
            decrypted.unwrap()
        };

        let secret = decrypted_parts.secret();
        if let sequoia_openpgp::packet::prelude::SecretKeyMaterial::Unencrypted(secret) = secret {
            secret
                .map(|key_material| -> Result<()> {
                    let key_role = {
                        if key.for_storage_encryption() || key.for_transport_encryption() {
                            KeyRole::Encrypt
                        } else {
                            KeyRole::Sign
                        }
                    };
                    match key_material {
                        SecretKeyMaterial::RSA { d: _, p, q, u: _ } => {
                            let key_type = KeyType::Rsa(key.mpis().bits().unwrap_or_default());
                            let mut secret_val: Vec<u8> = p
                                .value_padded(key.mpis().bits().unwrap_or_default() / 2 / 8)
                                .to_vec();
                            secret_val.extend_from_slice(
                                &q.value_padded(key.mpis().bits().unwrap_or_default() / 2 / 8),
                            );
                            onlykey.set_private(*slot, key_type, key_role, &secret_val)?;
                            Ok(())
                        }
                        SecretKeyMaterial::EdDSA { scalar }
                        | SecretKeyMaterial::ECDSA { scalar }
                        | SecretKeyMaterial::ECDH { scalar } => {
                            let key_type = match key.mpis() {
                                sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q: _ }
                                | sequoia_openpgp::crypto::mpi::PublicKey::ECDSA { curve, q: _ }
                                | sequoia_openpgp::crypto::mpi::PublicKey::ECDH {
                                    curve,
                                    q: _,
                                    hash: _,
                                    sym: _,
                                } => match curve {
                                    Curve::NistP256 => {
                                        KeyType::Ecc(ok_gpg_agent::config::EccType::Nist256P1)
                                    }
                                    Curve::Ed25519 => {
                                        KeyType::Ecc(ok_gpg_agent::config::EccType::Ed25519)
                                    }
                                    Curve::Cv25519 => {
                                        KeyType::Ecc(ok_gpg_agent::config::EccType::Cv25519)
                                    }
                                    _ => bail!("Wrong key type"),
                                },
                                _ => bail!("Non coherent key type"),
                            };
                            onlykey.set_private(
                                *slot,
                                key_type,
                                key_role,
                                &scalar.value_padded(32),
                            )?;
                            Ok(())
                        }
                        _ => Err(anyhow!("Wrong key type")),
                    }
                })
                .with_context(|| {
                    format!(
                        "Could not transfer the private key \"{}\"",
                        key_info_str(&key, *primary)
                    )
                })?;

            println!(
                "Key \"{}\" successfully transferred to slot {}!",
                key_info_str(&key, *primary),
                slot
            );
        }
    }

    println!("All keys successfully transferred.");
    for (index, slot, primary) in keys_slots {
        println!(
            "Key \"{}\" of ID {} transferred to slot {}",
            key_info_str(&key.keys().nth(index).unwrap(), primary),
            key.keys().nth(index).unwrap().fingerprint(),
            slot
        );
    }
    Ok(())
}

/// Display (println) the given key in a similar format as GPG does.
///
/// Output similar to `gpg -K --with-subkey-fingerprints`.
fn display_key(key: &ValidCert) {
    let primary = key.primary_key();

    // Primary key
    println!("0: {}", key_info_str(&primary, true));
    println!(
        "         {fingerprint}",
        fingerprint = primary.fingerprint()
    );
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
where
    P: 'a + sequoia_openpgp::packet::key::KeyParts,
    R: 'a + sequoia_openpgp::packet::key::KeyRole,
    R2: Copy,
    ValidKeyAmalgamation<'a, P, R, R2>: ValidAmalgamation<'a, Key<P, R>>,
{
    let sec = if primary {
        if has_secret(key) {
            "sec "
        } else {
            "sec#"
        }
    } else if has_secret(key) {
        "ssb "
    } else {
        "ssb#"
    };
    let creation_time: DateTime<Local> = key.creation_time().into();
    format!("{sec}  {type} {creation_time} {usage} {expiration}",
        type=algo_str(key),
        creation_time=creation_time.format("%Y-%m-%d"),
        usage=usage_str(key),
        expiration=expiration_str(key),
    )
}

fn has_secret<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> bool
where
    P: 'a + sequoia_openpgp::packet::key::KeyParts,
    R: 'a + sequoia_openpgp::packet::key::KeyRole,
    R2: Copy,
{
    match key.key().optional_secret() {
        None => false,
        Some(sequoia_openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)) => {
            !matches!(
                encrypted.s2k(),
                sequoia_openpgp::crypto::S2K::Private {
                    tag: 101,
                    parameters: _
                }
            ) // GnuPG extension for offline master key
        }
        _ => true,
    }
}

fn algo_str<'a, P, R, R2>(key: &ValidKeyAmalgamation<'a, P, R, R2>) -> String
where
    P: 'a + sequoia_openpgp::packet::key::KeyParts,
    R: 'a + sequoia_openpgp::packet::key::KeyRole,
    R2: Copy,
{
    match key.mpis() {
        sequoia_openpgp::crypto::mpi::PublicKey::RSA { .. } => {
            format!("rsa{}", key.mpis().bits().unwrap_or_default())
        }
        sequoia_openpgp::crypto::mpi::PublicKey::DSA { .. } => {
            format!("dsa{}", key.mpis().bits().unwrap_or_default())
        }
        sequoia_openpgp::crypto::mpi::PublicKey::ElGamal { .. } => "elgamal".to_string(),
        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q: _ } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::ECDSA { curve, q: _ } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::ECDH {
            curve,
            q: _,
            hash: _,
            sym: _,
        } => curve_to_str(curve),
        sequoia_openpgp::crypto::mpi::PublicKey::Unknown { mpis: _, rest: _ } => {
            "unknown".to_string()
        }
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
where
    P: 'a + sequoia_openpgp::packet::key::KeyParts,
    R: 'a + sequoia_openpgp::packet::key::KeyRole,
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
where
    P: 'a + sequoia_openpgp::packet::key::KeyParts,
    R: 'a + sequoia_openpgp::packet::key::KeyRole,
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
    (  ) => {{
        read!("{}\r\n")
    }};
}

#[cfg(unix)]
#[macro_export]
macro_rules! read_line {
    ( $( $x:expr ),* ) => {{
        read!("{}\n")
    }};
}
