use std::{path::{Path, PathBuf}};

use anyhow::{Result};
use config::{ConfigError, Config, File};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const fn _default_true() -> bool { true }
const fn _default_false() -> bool { false }

const fn _default_log_level() -> log::LevelFilter { log::LevelFilter::Info}

fn deserialize_log_level_filter<'de, D>(deserializer: D) -> Result<log::LevelFilter, D::Error>
where D: Deserializer<'de> {
    let buf = String::deserialize(deserializer)?;
    
    match buf.to_lowercase().as_ref() {
        "off" => Ok(log::LevelFilter::Off),
        "error" => Ok(log::LevelFilter::Error),
        "warn" => Ok(log::LevelFilter::Warn),
        "info" => Ok(log::LevelFilter::Info),
        "debug" => Ok(log::LevelFilter::Debug),
        "trace" => Ok(log::LevelFilter::Trace),
        s => Err(serde::de::Error::custom(format!("not a valid log level: {}", s))),
    }
}

fn serialize_log_level_filter<S>(log_level: &log::LevelFilter, s: S) -> Result<S::Ok, S::Error>
where S: Serializer {
    s.serialize_str(match log_level {
        log::LevelFilter::Off => "off",
        log::LevelFilter::Error => "error",
        log::LevelFilter::Warn => "warn",
        log::LevelFilter::Info => "info",
        log::LevelFilter::Debug => "debug",
        log::LevelFilter::Trace => "trace",
    })
}

#[derive(PartialEq)]
pub enum KeyType {
    Rsa(usize),
    Ecc(EccType),
}

#[derive(Debug, Deserialize, Serialize)]
#[derive(Clone, PartialEq)]
pub enum EccType {
    Unkwnow,
    Ed25519,
    Cv25519,
    Nist256P1,
    Secp256K1
}

#[derive(Debug, Deserialize, Serialize)]
#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum KeySlot {
    RSA1 = 1, RSA2 = 2, RSA3 = 3, RSA4 = 4,

    ECC1  = 101, ECC2  = 102, ECC3  = 103, ECC4  = 104,
    ECC5  = 105, ECC6  = 106, ECC7  = 107, ECC8  = 108,
    ECC9  = 109, ECC10 = 110, ECC11 = 111, ECC12 = 112,
    ECC13 = 113, ECC14 = 114, ECC15 = 115, ECC16 = 116,
}

#[derive(Debug, Deserialize, Serialize)]
#[derive(Clone)]
#[serde(untagged)]
pub enum KeyInfo {
    StoredKey(StoredKeyInfo),
    DerivedKey(DerivedKeyInfo)
}

impl KeyInfo {
    pub fn slot_nb(&self) -> u8 {
        match self {
            KeyInfo::StoredKey(keyinfo) => keyinfo.slot_nb(),
            KeyInfo::DerivedKey(keyinfo) => keyinfo.slot_nb(),
        }
    }

    pub fn r#type(&self) -> KeyType {
        match self {
            KeyInfo::StoredKey(keyinfo) => keyinfo.r#type(),
            KeyInfo::DerivedKey(keyinfo) => keyinfo.r#type(),
        }
    }

    pub fn keygrip(&self) -> String {
        match self {
            KeyInfo::StoredKey(key) => key.keygrip.clone(),
            KeyInfo::DerivedKey(key) => key.keygrip.clone(),
        }
    }
}

/// Info about a key as stored in the config file
#[derive(Debug, Deserialize, Serialize)]
#[derive(Clone)]
pub struct StoredKeyInfo {
    /// The slot of the OnlyKey on which the private part of this key is stored
    /// 
    /// Slot may be RSA1-RSA4 ECC1-ECC16
    pub slot: KeySlot,
    /// The keygrip of this key
    pub keygrip: String,
    /// The size of the public key in bits
    /// Only required for RSA keys.
    #[serde(default)]
    pub size: usize,
}

impl StoredKeyInfo {
    pub fn slot_nb(&self) -> u8 {
        self.slot as u8
    }

    pub fn r#type(&self) -> KeyType {
        match self.slot {
            KeySlot::RSA1 | KeySlot::RSA2 | KeySlot::RSA3 | KeySlot::RSA4 => KeyType::Rsa(self.size),
            KeySlot::ECC1  | KeySlot::ECC2  | KeySlot::ECC3  | KeySlot::ECC4  |
            KeySlot::ECC5  | KeySlot::ECC6  | KeySlot::ECC7  | KeySlot::ECC8  |
            KeySlot::ECC9  | KeySlot::ECC10 | KeySlot::ECC11 | KeySlot::ECC12 |
            KeySlot::ECC13 | KeySlot::ECC14 | KeySlot::ECC15 | KeySlot::ECC16 => KeyType::Ecc(EccType::Unkwnow),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[derive(Clone)]
pub struct DerivedKeyInfo {
    /// Identity linked to the key ("Name <name@mail.com>")
    pub identity: String,
    /// Type of the key
    pub ecc_type: EccType,
    /// The keygrip of this key
    pub keygrip: String,
}

impl DerivedKeyInfo {
    pub fn slot_nb(&self) -> u8 {
        match self.ecc_type {
            EccType::Unkwnow => 132,
            EccType::Ed25519 => 201,
            EccType::Nist256P1 => 202,
            EccType::Secp256K1 => 203,
            EccType::Cv25519 => 204,
        }
    }

    pub fn r#type(&self) -> KeyType {
        KeyType::Ecc(self.ecc_type.clone())
    }

    pub fn algo_nb(&self) -> u8 {
        match self.ecc_type {
            EccType::Unkwnow => 0,
            EccType::Ed25519 => 1,
            EccType::Nist256P1 => 2,
            EccType::Secp256K1 => 3,
            EccType::Cv25519 => 4,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[derive(Clone)]
pub struct Settings {
    /// Use challenge for operations
    #[serde(default = "_default_true")]
    pub challenge: bool,
    /// Max log level
    #[serde(deserialize_with = "deserialize_log_level_filter", serialize_with = "serialize_log_level_filter", default = "_default_log_level")]
    pub log_level: log::LevelFilter,
    /// Path to the gpg-agent to use
    #[serde(default)]
    pub agent_program: PathBuf,
    /// Delete socket if already present
    #[serde(default = "_default_false")]
    pub delete_socket: bool,
    /// Known keys
    #[serde(default)]
    pub keyinfo: Vec<KeyInfo>,
}

impl Settings {
    pub fn new(config_file: &Path) -> Result<Self, ConfigError> {

        let s = Config::builder()
            .add_source(File::from(config_file))
            .build()?;

        s.try_deserialize()
    }
}