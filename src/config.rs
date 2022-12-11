use std::{path::{Path, PathBuf}, collections::HashMap};

use anyhow::{Result};
use thiserror::Error;
use config::{ConfigError, Config, File};
use serde::{Deserialize, Deserializer};

const fn _default_true() -> bool { true }

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

#[derive(PartialEq)]
pub enum KeyType {
    Rsa(usize),
    Ecc(EccType),
}

#[derive(Debug, Deserialize)]
#[derive(Clone, PartialEq)]
pub enum EccType {
    Unkwnow,
    Ed25519,
    Cv25519,
    Nist256P1,
    Secp256K1
}

#[derive(Error, Debug)]
pub enum KeyInfoError {
    #[error("Unkwnow slot name: {0}")]
    UnkwnownSlotName(String),
}

#[derive(Debug, Deserialize)]
#[derive(Clone)]
#[serde(untagged)]
pub enum KeyInfo {
    StoredKey(StoredKeyInfo),
    DerivedKey(DerivedKeyInfo)
}

impl KeyInfo {
    pub fn slot_nb(&self) -> Result<u8, KeyInfoError> {
        match self {
            KeyInfo::StoredKey(keyinfo) => keyinfo.slot_nb(),
            KeyInfo::DerivedKey(keyinfo) => keyinfo.slot_nb(),
        }
    }

    pub fn r#type(&self) -> Result<KeyType, KeyInfoError> {
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
#[derive(Debug, Deserialize)]
#[derive(Clone)]
pub struct StoredKeyInfo {
    /// The slot of the OnlyKey on which the private part of this key is stored
    /// 
    /// Slot may be RSA1-RSA4 ECC1-ECC16
    pub slot: String,
    /// The keygrip of this key
    pub keygrip: String,
    /// The size of the public key in bits
    /// Only required for RSA keys.
    #[serde(default)]
    pub size: usize,
}

impl StoredKeyInfo {
    pub fn slot_nb(&self) -> Result<u8, KeyInfoError> {
        let mut map = HashMap::new();
        for i in 1..=4 {
            map.insert(format!("RSA{}", i), i);
        }
        for i in 1..=16 {
            map.insert(format!("ECC{}", i), i+100);
        }
        map.get(&self.slot).copied().ok_or_else(|| KeyInfoError::UnkwnownSlotName(self.slot.clone()))
    }

    pub fn r#type(&self) -> Result<KeyType, KeyInfoError> {
        if self.slot.starts_with("RSA") {
            Ok(KeyType::Rsa(self.size))
        } else if self.slot.starts_with("ECC") {
            Ok(KeyType::Ecc(EccType::Unkwnow))
        } else {
            Err(KeyInfoError::UnkwnownSlotName(self.slot.clone()))
        }
    }
}

#[derive(Debug, Deserialize)]
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
    pub fn slot_nb(&self) -> Result<u8, KeyInfoError> {
        Ok(match self.ecc_type {
            EccType::Unkwnow => 132,
            EccType::Ed25519 => 201,
            EccType::Nist256P1 => 202,
            EccType::Secp256K1 => 203,
            EccType::Cv25519 => 204,
        })
    }

    pub fn r#type(&self) -> Result<KeyType, KeyInfoError> {
        Ok(KeyType::Ecc(self.ecc_type.clone()))
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

#[derive(Debug, Deserialize)]
#[derive(Clone)]
pub struct Settings {
    /// Use challenge for operations
    #[serde(default = "_default_true")]
    pub challenge: bool,
    /// Max log level
    #[serde(deserialize_with = "deserialize_log_level_filter", default = "_default_log_level")]
    pub log_level: log::LevelFilter,
    /// Path to the gpg-agent to use
    #[serde(default)]
    pub agent_program: PathBuf,
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