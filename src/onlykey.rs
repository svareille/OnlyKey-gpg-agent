use std::{sync::{Mutex, Arc}, time::{Duration, SystemTime, Instant}, fmt::Debug};

use hidapi::{HidDevice, HidApi};
use log::{trace, debug, info, warn, error};
use sha2::{Sha256, Digest};
use strum::IntoEnumIterator;
use thiserror::Error;

use crate::config::{KeyInfo, KeyType, EccType, KeySlot, StoredKeyInfo};

#[cfg(windows)]
const MESSAGE_HEADER : [u8; 5] = [0u8, 255, 255, 255, 255];
#[cfg(windows)]
const REPORT_SIZE: usize = 65;
#[cfg(unix)]
const MESSAGE_HEADER : [u8; 4] = [255u8, 255, 255, 255];
#[cfg(unix)]
const REPORT_SIZE: usize = 64;

const OKSETTIME: u8 = 0xe4;
const OKSIGN: u8 = 237;
const OKDECRYPT: u8 = 240;
const OKGETPUBKEY: u8 = 236;
const OKSETPRIV: u8 = 239;

pub const OK_DEVICE_IDS: [(u16, u16); 2] = [(0x16C0, 0x0486), (0x1d50, 0x60fc)];

#[derive(Debug)]
#[derive(Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum KeyRole {
    Encrypt = 32,
    Sign = 64,
    Backup = 128 + 32,
}


#[derive(Error, Debug)]
pub enum OnlyKeyError {
    #[error("Bytes are not UTF-8")]
    NotUtf8,
    #[error("Unkwnow slot name {0}")]
    UnkwnownSlotName(String),
    #[error("Wrong ECC slot")]
    WrongEccSlot,
    #[error("Wrong RSA slot")]
    WrongRsaSlot,
    #[error("OnlyKey not initialized")]
    NotInitialized,
    #[error("OnlyKey locked")]
    Locked,
    #[error("OnlyKey not in config mode")]
    NotInConfigMode,
    #[error("No key set in the slot {0}")]
    NoKeySet(String),
    #[error("Key {0} not set as signature key")]
    NotASignatureKey(String),
    #[error("Key {0} not set as decryption key")]
    NotADecryptionKey(String),
    #[error("Invalid data size")]
    InvalidDataSize,
    #[error("Signature failed")]
    SignFailed,
    #[error("Decryption failed")]
    DecryptFailed,
    #[error("Invalid ECC type")]
    InvalidEccType,
    #[error("Invalid RSA type")]
    InvalidRsaType,
    #[error("Wrong challenge")]
    WrongChallenge,
    #[error("Public key generation failed: {0}")]
    PublicKeyGenerationFailed(String),
    #[error("Timeout occured while waiting for user input")]
    Timeout,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    HIDError(#[from] hidapi::HidError),
    #[error("Other error: {0}")]
    Other(String),
}

pub struct OnlyKey {
    pub device: HidDevice,
    pub unlocked: bool,
    pub connected: bool,
    pub version: String,
}

impl OnlyKey {
    pub fn hid_connect() -> Result<Option<OnlyKey>, OnlyKeyError> {
        let api = HidApi::new()?;
        for device in api.device_list() {
            if OK_DEVICE_IDS.contains(&(device.vendor_id(), device.product_id())) {
                if device.serial_number() == Some("1000000000") {
                    if device.usage_page() == 0xffab || device.interface_number() == 2 {
                        info!("Found Onlykey device at {}:{}", device.vendor_id(), device.product_id());
                        return OnlyKey::new(device.open_device(&api)?).map(Some);
                    }
                }
                else if device.usage_page() == 0xf1d0 || device.interface_number() == 1 {
                    info!("Found Onlykey device at {}:{}", device.vendor_id(), device.product_id());
                    return OnlyKey::new(device.open_device(&api)?).map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Try to connect to an OnlyKey.
    /// 
    /// If the connection is successful, open a thread monitoring the key.
    pub fn try_connection() -> Result<Option<Arc<Mutex<Self>>>, OnlyKeyError> {
        let onlykey = OnlyKey::hid_connect()?;

        let onlykey = onlykey.map(|ok| Arc::new(Mutex::new(ok)));

        if let Some(ok) = &onlykey {
            let ok = ok.clone();
            std::thread::spawn(move || {
                while ok.lock().unwrap().connected {
                    if !ok.lock().unwrap().unlocked {
                        // OnlyKey locked, it sends "INITIALIZED" every 500ms until unlocked
                        let mut ok = ok.lock().unwrap();
                        match ok.read_timeout(Some(Duration::ZERO)) {
                            Ok(data) => {
                                ok.connected = true;

                                let msg = String::from_utf8(data.split(|&c|c==0).next().unwrap_or_default().to_vec()).unwrap_or_default();
                                ok.handle_msg(&msg);

                                if !ok.unlocked {
                                    drop(ok);
                                    std::thread::sleep(Duration::from_millis(500));
                                } else {
                                    info!("Onlykey unlocked");
                                    std::thread::sleep(Duration::from_millis(1));
                                }
                            },
                            Err(e) => {
                                warn!("Could not read device: {}", e);
                                ok.unlocked = false;
                                ok.connected = false;
                                return;
                            }
                        }
                    } else {
                        // OnlyKey unlocked, we send OKSETTIME every 1 sec to detect if key becomes
                        // locked
                        let mut ok = ok.lock().unwrap();

                        if let Err(e) = ok.set_time() {
                            warn!("Could not set time of device: {}", e);
                            ok.unlocked = false;
                            ok.connected = false;
                            return;
                        }

                        if ok.unlocked {
                            drop(ok);
                            std::thread::sleep(Duration::from_secs(1));
                        } else {
                            info!("Onlykey locked");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
            });
        }

        Ok(onlykey)
    }

    pub fn new(device: HidDevice) -> Result<Self, OnlyKeyError> {
        let mut buf = [];
        let connected = device.read_timeout(&mut buf, 0).is_ok();
        let mut ok = OnlyKey {device, unlocked: false, connected, version: String::new()};
        ok.set_time()?;
        Ok(ok)
    }

    /// Disconnect the device, consequently shutting down the related thread.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    pub fn set_time(&mut self) -> Result<(), OnlyKeyError> {
        trace!("Setting time for device");
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("System time before UNIX EPOCH! Something definetly went wrong!")
            .as_secs();

        let time_str = format!("{:x}", time);
        let time_str = format!("{:0fill$}", time, fill = time_str.len() + time_str.len()%2);

        let payload: Vec<u8> = hex::decode(time_str).expect("The time should have been hex-encoded already");

        self.send(OKSETTIME, &payload)?;

        let resp = self.read_string()?;
        self.handle_msg(&resp);

        trace!("Time set!");
        Ok(())
    }

    pub fn read_string(&self) -> Result<String, OnlyKeyError> {
        let s = String::from_utf8(self.read()?
                                          .split(|&c|c==0)
                                          .next().unwrap_or_default().to_vec()
                                        ).map_err(|_| OnlyKeyError::NotUtf8)?;
        Ok(s)
    }

    pub fn read(&self) -> Result<Vec<u8>, OnlyKeyError> {
        self.read_timeout(None)
    }

    pub fn read_timeout(&self, timeout: Option<Duration>) -> Result<Vec<u8>, OnlyKeyError> {
        self.device.set_blocking_mode(true)?;
        let mut buf = vec![0; 64];

        let timeout = match timeout {
            Some(t) => i32::try_from(t.as_millis()).unwrap_or(i32::MAX),
            None => -1,
        };
        let len = self.device.read_timeout(&mut buf, timeout)?;

        buf.resize(len, 0);

        //debug!("[OnlyKey] Got {:?}", buf);
        Ok(buf)
    }

    fn handle_msg(&mut self, msg: &str) {
        match msg {
            "INITIALIZED" => {
                self.unlocked = false;
            }
            str => {
                if let Some(stripped) = str.strip_prefix("UNLOCKED") {
                    self.unlocked = true;
                    self.version = stripped.to_owned();
                }
            }
        }
    }

    pub fn send(&self, msg_type: u8, payload: &[u8]) -> Result<(), OnlyKeyError> {
        let mut message: Vec<u8> = MESSAGE_HEADER.into();
        message.push(msg_type);
        message.extend_from_slice(payload);

        self.device.write(&message)?;
        Ok(())
    }

    /// Send a payload to the given slot.
    /// 
    /// Split the message in chunks if required.
    pub fn send_with_slot(&self, msg_type: u8, slot: u8, payload: &[u8]) -> Result<(), OnlyKeyError> {
        trace!("Sending message to device");

        let max_payload = REPORT_SIZE - MESSAGE_HEADER.len() - 3;

        trace!("max payload: {}, total length: {}", max_payload, payload.len());

        let mut chunks = payload.chunks(max_payload).peekable();
        trace!("Message is {} chunks", chunks.len());
        while let Some(chunk) = chunks.next() {
            let mut payload = vec![slot, 255];
            if chunks.peek().is_none() {
                payload[1] = chunk.len() as u8;
            }
            payload.extend_from_slice(chunk);
            self.send(msg_type, &payload)?;
        }
        Ok(())
    }

    fn gpg_identity_derivation(identity: &str) -> Vec<u8> {
        let identity = format!("gpg://{}", identity).into_bytes();
        Sha256::new()
            .chain_update(identity)
            .finalize().to_vec()
    }

    pub fn data_to_send(data: &[u8], key: &KeyInfo) -> Vec<u8> {
        match key {
            KeyInfo::StoredKey(_) => data.to_vec(),
            KeyInfo::DerivedKey(key) => {
                let mut identity = Self::gpg_identity_derivation(&key.identity);
                let mut data = data.to_vec();
                data.append(&mut identity);
                data
            },
        }
    }

    pub fn pubkey(&self, key: &KeyInfo) -> Result<Vec<u8>, OnlyKeyError> {
        let mut data: Vec<u8>;
        match key {
            KeyInfo::StoredKey(key) => {
                let slot = key.slot_nb();
                data = vec![slot, 0];
                // TODO: place in data the exact key type or ask OnlyKey developer to patch the firmware
            },
            KeyInfo::DerivedKey(key) => {
                let identity = Self::gpg_identity_derivation(&key.identity);
                data = vec![132, key.algo_nb()];
                data.extend_from_slice(&identity);
            },
        }

        // Time to wait for response
        let wait_for = Duration::from_millis(1500);

        self.send(OKGETPUBKEY, &data)?;

        let start = Instant::now();
        let mut got_last_packet = None;
        let mut result = Vec::new();

        while start.elapsed() < wait_for {
            let part = self.read_timeout(Some(Duration::from_millis(100)))?;
            if part.len() == 64 && part[..63].windows(2).any(|elem| elem[0] != elem[1]) {
                // Got good part
                self.error_parser(&part, key)?;
                got_last_packet = Some(Instant::now());
                match key.r#type() {
                    KeyType::Ecc(_) => {
                        // We got everything
                        result = part;
                        break;
                    },
                    KeyType::Rsa(size) => {
                        // We got a part of the public key
                        result.extend(part);

                        if size != 0 && result.len() >= size/8 {
                            break;
                        }
                    }
                }
            }
            if let KeyType::Rsa(0) = key.r#type() {
                // We don't actually know the size, so we guess
                if got_last_packet.is_some() && got_last_packet.unwrap().elapsed() >= Duration::from_millis(100) {
                    // It seems we got everything
                    break;
                }
            }
        }

        if start.elapsed() >= wait_for {
            debug!("Timeout reading public key");
        }
        if result.is_empty() {
            return Err(OnlyKeyError::PublicKeyGenerationFailed("No data received".to_owned()));
        }

        match key.r#type() {
            KeyType::Ecc(t) => {
                if result[34..63].windows(2).all(|elem| elem[0] == elem[1]) {
                    // Key should be ed25519 or cv25519
                    if t == EccType::Nist256P1 || t == EccType::Secp256K1 {
                        return Err(OnlyKeyError::PublicKeyGenerationFailed("Public key curve does not match requested type".to_owned()));
                    }
                    result.resize(32, 0);
                    Ok(result)
                } else {
                    // Key should be nist256 or secp256
                    if t == EccType::Ed25519 || t == EccType::Cv25519 {
                        return Err(OnlyKeyError::PublicKeyGenerationFailed("Public key curve does not match requested type".to_owned()));
                    }
                    Ok(result)
                }
            },
            KeyType::Rsa(size) => {
                if size != 0 && result.len() > size/8 {
                    result.resize(size/8, 0);
                }
                Ok(result)
            }
        }
    }

    pub fn sign(&self, data: &[u8], sign_key: &KeyInfo) -> Result<Vec<u8>, OnlyKeyError> {
        let slot = sign_key.slot_nb();

        let data = OnlyKey::data_to_send(data, sign_key);

        // Time to wait for user interaction
        let wait_for = Duration::from_secs(22);

        self.send_with_slot(OKSIGN, slot, &data)?;

        let start = Instant::now();
        let mut result = Vec::new();

        while start.elapsed() < wait_for {
            let part = self.read_timeout(Some(Duration::from_millis(100)))?;
            if part.len() == 64 && part[..63].windows(2).any(|elem| elem[0] != elem[1]) {
                // Got good part
                self.error_parser(&part, sign_key)?;
                match sign_key.r#type() {
                    KeyType::Ecc(_) => {
                        // We got everything
                        result = part;
                        break;
                    },
                    KeyType::Rsa(size) => {
                        // We got a part of the signature
                        result.extend(part);

                        if result.len() >= size/8 {
                            break;
                        }
                    }
                }
            }
        }

        if start.elapsed() >= wait_for {
            debug!("Timeout reading signature");
        }

        match sign_key.r#type() {
            KeyType::Ecc(_) => {
                if result.len() >= 60 {
                    //debug!("Got signature {} of length {}", hex::encode(result.clone()), result.len());
                    result.resize(64, 0);
                    return Ok(result);
                } 
            },
            KeyType::Rsa(size) => {
                if result.len() > size/8 {
                    result.resize(size/8, 0);
                }
                return Ok(result);
            },
        }
        error!("Signature failed. Got {:?}", result);
        Err(OnlyKeyError::SignFailed)
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &KeyInfo) -> Result<Vec<u8>, OnlyKeyError> {
        let slot = key.slot_nb();

        let data = OnlyKey::data_to_send(ciphertext, key);

        // Time to wait for user interaction
        let wait_for = Duration::from_secs(22);

        self.send_with_slot(OKDECRYPT, slot, &data)?;

        let start = Instant::now();
        let mut result = Vec::new();
        let mut key_len = None;
        while start.elapsed() < wait_for {
            let part = self.read_timeout(Some(Duration::from_millis(100)))?;
            if part.len() == 64 && part[..63].windows(2).any(|elem| elem[0] != elem[1]) {
                // Got good part
                self.error_parser(&part, key)?;
                match key.r#type() {
                    KeyType::Ecc(_) => {
                        // We got everything
                        result = part;
                        break;
                    },
                    KeyType::Rsa(_) => {
                        // We got a part of the plaintext. Check which algorithm is in use to
                        // know how much data is sent

                        if key_len.is_none() {
                            key_len = Some(openpgp_cipher_get_algo_keylen(part[0])/8);
                        }
                        result.extend(part);

                        if result.len() >= key_len.unwrap()+3 {
                            result.resize(key_len.unwrap()+3, 0);
                            break;
                        }
                    }
                }
            }
        }

        if start.elapsed() >= wait_for {
            debug!("Timeout reading decrypted data");
        }

        if let KeyType::Ecc(_) = key.r#type() {
            if let Some(r) = result.get(34..63) {
                // As per https://www.rfc-editor.org/rfc/rfc6637.html#section-6, an OpenPGP MPI
                // begins with the byte 0x04
                if !r.windows(2).any(|elem| elem[0] != elem[1]) {
                    // Response is 32 bytes long
                    let mut r = result[..32].to_vec();
                    result = vec![b'\x04'];
                    result.append(&mut r);
                } else {
                    // Response is 64 bytes long
                    let mut r = result[..64].to_vec();
                    result = vec![b'\x04'];
                    result.append(&mut r);
                }
            }
            return Ok(result);
        } else if let KeyType::Rsa(_) = key.r#type() {
            // We only got the plaintext key, we need to encode it in a PKCS#1 packet
            let mut padding = Vec::new();
            padding.resize(256 - result.len() - 3, 0xFF);
            let mut res = vec![0, 2];
            res.append(&mut padding);
            res.push(0);
            res.append(&mut result);
            result = res;
            return Ok(result);
        }

        error!("Decryption failed. Got {:?}", result);
        Err(OnlyKeyError::DecryptFailed)
    }

    pub fn set_private(&self, slot: KeySlot, key_type: KeyType, key_role: KeyRole, key: &[u8]) -> Result<(), OnlyKeyError> {
        // buffer[6] = type
        // buffer[5] = slot
        // buffer[4] = msgtype
        // buffer[0] = 0xBA for last packet // Optional
        let mut key_type: u8 = match key_type {
            KeyType::Rsa(size) => {
                (size / 1024) as u8
            },
            KeyType::Ecc(ecc_type) => {
                match ecc_type {
                    EccType::Unkwnow => return Err(OnlyKeyError::InvalidEccType),
                    EccType::Ed25519 | EccType::Cv25519 => 1,
                    EccType::Nist256P1 => 2,
                    EccType::Secp256K1 => 3,
                }
            },
        };

        key_type |= key_role as u8;

        let max_payload = REPORT_SIZE - MESSAGE_HEADER.len() - 3;

        let chunks = key.chunks(max_payload);
        
        for chunk in chunks {
            let mut payload = vec![slot as u8, key_type];
            payload.extend_from_slice(chunk);
            self.send(OKSETPRIV, &payload)?;
        }

        let response = self.read_timeout(Some(Duration::from_millis(100)))?;
        self.error_parser(&response, &KeyInfo::StoredKey(StoredKeyInfo { slot, keygrip: String::new(), size: 0 }))?;

        Ok(())
    }

    /// Return a list of empty key slots.
    pub fn get_empty_key_slots(&self) -> Result<Vec<KeySlot>, OnlyKeyError> {
        let mut empty_slots = Vec::new();
        for slot in KeySlot::iter() {
            debug!("Testing slot {}", slot);
            match self.pubkey(&KeyInfo::StoredKey(StoredKeyInfo {
                slot,
                keygrip: String::new(),
                size: 0,
            })) {
                Err(OnlyKeyError::NoKeySet(_)) => empty_slots.push(slot),
                Err(e) => return Err(e),
                Ok(pubkey) => {
                    debug!("Pubkey for {} is {:?}", slot, pubkey);
                    trace!("Slot {} occupied", slot);
                },
            }
        }
        Ok(empty_slots)
    }

    pub fn compute_challenge(data: &[u8]) -> (u8, u8, u8) {
        // Compute challenge
        let h1 = Sha256::new()
        .chain_update(data)
        .finalize();
        (OnlyKey::get_button(h1[0]), OnlyKey::get_button(h1[15]), OnlyKey::get_button(h1[31]))
    }

    fn error_parser(&self, data: &[u8], key: &KeyInfo) -> Result<(), OnlyKeyError> {
        match String::from_utf8(data.split(|&c|c==0)
        .next().unwrap_or_default().to_vec()).unwrap_or_default().as_ref() {
            "INITIALIZED" => Err(OnlyKeyError::Locked),
            "Error incorrect challenge was entered" => Err(OnlyKeyError::WrongChallenge),
            "Error no key set in this slot" => Err(OnlyKeyError::NoKeySet(match key {
                KeyInfo::StoredKey(key) => key.slot.to_string(),
                KeyInfo::DerivedKey(_) => "Derived key".to_string(),
            })),
            "Error key not set as signature key" => Err(OnlyKeyError::NotASignatureKey(match key {
                KeyInfo::StoredKey(key) => key.slot.to_string(),
                KeyInfo::DerivedKey(_) => "Derived key".to_string(),
            })),
            "Error key not set as decryption key" => Err(OnlyKeyError::NotADecryptionKey(match key {
                KeyInfo::StoredKey(key) => key.slot.to_string(),
                KeyInfo::DerivedKey(_) => "Derived key".to_string(),
            })),
            "Error with RSA data to sign invalid size" => Err(OnlyKeyError::InvalidDataSize),
            "Error with RSA signing" => Err(OnlyKeyError::SignFailed),
            "Error with RSA data to decrypt invalid size" => Err(OnlyKeyError::InvalidDataSize),
            "Error with RSA decryption" => Err(OnlyKeyError::DecryptFailed),
            "Error ECC type incorrect" => Err(OnlyKeyError::InvalidEccType),
            s@"Error invalid key, key check failed" => Err(OnlyKeyError::Other(s.to_owned())),
            s@"invalid data, or data does not match key" => Err(OnlyKeyError::Other(s.to_owned())),
            s@"Error invalid data, or data does not match key" => Err(OnlyKeyError::Other(s.to_owned())),
            s@"Error generating RSA public N" => Err(OnlyKeyError::PublicKeyGenerationFailed(s.to_owned())),
            "Error you must set a PIN first on OnlyKey" => Err(OnlyKeyError::NotInitialized),
            "Error device locked" => Err(OnlyKeyError::Locked),
            "Error not in config mode, hold button 6 down for 5 sec" => Err(OnlyKeyError::NotInConfigMode),
            "No PIN set, You must set a PIN first" => Err(OnlyKeyError::NotInitialized),
            "Error invalid ECC slot" => Err(OnlyKeyError::WrongEccSlot),
            "Error no ECC Private Key set in this slot" => Err(OnlyKeyError::NoKeySet(match key {
                KeyInfo::StoredKey(key) => key.slot.to_string(),
                KeyInfo::DerivedKey(_) => "Derived key".to_string(),
            })),
            "Error invalid RSA slot" => Err(OnlyKeyError::WrongRsaSlot),
            "Error no RSA Private Key set in this slot" => Err(OnlyKeyError::NoKeySet(match key {
                KeyInfo::StoredKey(key) => key.slot.to_string(),
                KeyInfo::DerivedKey(_) => "Derived key".to_string(),
            })),
            "Error invalid RSA type" => Err(OnlyKeyError::InvalidRsaType),
            "Timeout occured while waiting for confirmation on OnlyKey" => Err(OnlyKeyError::Timeout),
            _ => Ok(()),
        }
    }

    /// Return a button number corresponding to the given byte
    pub fn get_button(byte: u8) -> u8 {
        byte % 6 + 1
    }
}

impl Debug for OnlyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnlyKey").field("device", &self.device.get_product_string()).field("unlocked", &self.unlocked).field("connected", &self.connected).field("version", &self.version).finish()
    }
}


// Return the length of the key given the algorithm `algo`, in bits.
pub fn openpgp_cipher_get_algo_keylen(algo: u8) -> usize {
    match algo {
        1 => 128, // CIPHER_ALGO_IDEA
        2 => 192, // CIPHER_ALGO_3DES
        3 => 128, // CIPHER_ALGO_CAST5
        4 => 128, // CIPHER_ALGO_BLOWFISH
        7 => 128, // CIPHER_ALGO_AES
        8 => 192, // CIPHER_ALGO_AES192
        9 => 256, // CIPHER_ALGO_AES256
        10 => 256, // CIPHER_ALGO_TWOFISH
        11 => 128, // CIPHER_ALGO_CAMELLIA128
        12 => 192, // CIPHER_ALGO_CAMELLIA192
        13 => 256, // CIPHER_ALGO_CAMELLIA256
        _ => 0,
    }
}