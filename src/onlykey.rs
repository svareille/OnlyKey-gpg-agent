use std::{sync::{Mutex, Arc}, time::{Duration, SystemTime, Instant}};

use hidapi::{HidDevice, HidApi};
use log::{trace, debug, info, warn, error};
use thiserror::Error;

use crate::config::{KeyInfo, KeyInfoError, KeyType};

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

pub const OK_DEVICE_IDS: [(u16, u16); 2] = [(0x16C0, 0x0486), (0x1d50, 0x60fc)];


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
    #[error("Public key generation failed")]
    PublicKeyGenerationFailed,
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
    pub fn try_connection() -> Result<Option<Arc<Mutex<Self>>>, OnlyKeyError> {
        let api = HidApi::new()?;
        let mut onlykey = None;
        for device in api.device_list() {
            if OK_DEVICE_IDS.contains(&(device.vendor_id(), device.product_id())) {
                if device.serial_number() == Some("1000000000") {
                    if device.usage_page() == 0xffab || device.interface_number() == 2 {
                        info!("Found Onlykey device at {}:{}", device.vendor_id(), device.product_id());
                        onlykey = OnlyKey::new(device.open_device(&api)?).map(Some)?;
                    }
                }
                else if device.usage_page() == 0xf1d0 || device.interface_number() == 1 {
                    info!("Found Onlykey device at {}:{}", device.vendor_id(), device.product_id());
                    onlykey = OnlyKey::new(device.open_device(&api)?).map(Some)?;
                }
            }
        }

        let onlykey = onlykey.map(|ok| Arc::new(Mutex::new(ok)));

        if let Some(ok) = &onlykey {
            let ok = ok.clone();
            std::thread::spawn(move || {
                loop {
                    if !ok.lock().unwrap().unlocked {
                        // OnlyKey locked, it sends "INITIALIZED" every 500ms unitl unlocked
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

    pub fn set_time(&mut self) -> Result<(), OnlyKeyError> {
        trace!("Setting time for device");
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("System time before UNIX EPOCH! Something definetly went wrong!")
            .as_secs();

        let time_str = format!("{:x}", time);
        let time_str = format!("{:0fill$}", time, fill = time_str.len() + time_str.len()%2);

        let payload: Vec<u8> = hex::decode(time_str).expect("The time should have been hex-encoded already");

        self.send(OKSETTIME, payload)?;

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

    pub fn send(&self, msg_type: u8, mut payload: Vec<u8>) -> Result<(), OnlyKeyError> {
        let mut message: Vec<u8> = MESSAGE_HEADER.into();
        message.push(msg_type);
        message.append(&mut payload);

        self.device.write(&message)?;
        Ok(())
    }

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
            self.send(msg_type, payload)?;
        }
        Ok(())
    }

    pub fn sign(&self, data: &[u8], sign_key: &KeyInfo) -> Result<Vec<u8>, OnlyKeyError> {
        let slot = sign_key.slot_nb().map_err(|e|match e {
            KeyInfoError::UnkwnownSlotName(slot) => OnlyKeyError::UnkwnownSlotName(slot)
        })?;

        // Time to wait for user interaction
        let wait_for = Duration::from_secs(22);

        self.send_with_slot(OKSIGN, slot, data)?;

        let start = Instant::now();
        let mut result = Vec::new();

        while start.elapsed() < wait_for {
            let part = self.read_timeout(Some(Duration::from_millis(100)))?;
            if part.len() == 64 && part[..63].windows(2).any(|elem| elem[0] != elem[1]) {
                // Got good part
                self.error_parser(&part, sign_key)?;
                match sign_key.r#type().unwrap() {
                    KeyType::Ecc => {
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

        if sign_key.r#type().unwrap() == KeyType::Ecc {
            if result.len() >= 60 {
                //debug!("Got signature {} of length {}", hex::encode(result.clone()), result.len());
                result.resize(64, 0);
                return Ok(result);
            } 
        } else if let Ok(KeyType::Rsa(size)) = sign_key.r#type() {
            if result.len() > size/8 {
                result.resize(size/8, 0);
            }
            return Ok(result);
        }
        error!("Signature failed. Got {:?}", result);
        Err(OnlyKeyError::SignFailed)
    }

    pub fn decrypt(&self, ciphertext: &[u8], key: &KeyInfo) -> Result<Vec<u8>, OnlyKeyError> {
        let slot = key.slot_nb().map_err(|e|match e {
            KeyInfoError::UnkwnownSlotName(slot) => OnlyKeyError::UnkwnownSlotName(slot)
        })?;

        // Time to wait for user interaction
        let wait_for = Duration::from_secs(22);

        debug!("Sending {} bytes of ciphertext", ciphertext.len());

        self.send_with_slot(OKDECRYPT, slot, ciphertext)?;

        let start = Instant::now();
        let mut result = Vec::new();
        let mut key_len = None;
        while start.elapsed() < wait_for {
            let part = self.read_timeout(Some(Duration::from_millis(100)))?;
            if part.len() == 64 && part[..63].windows(2).any(|elem| elem[0] != elem[1]) {
                // Got good part
                self.error_parser(&part, key)?;
                match key.r#type().unwrap() {
                    KeyType::Ecc => {
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

        if key.r#type().unwrap() == KeyType::Ecc {
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
        } else if let Ok(KeyType::Rsa(_)) = key.r#type() {
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

    fn error_parser(&self, data: &[u8], key: &KeyInfo) -> Result<(), OnlyKeyError> {
        match String::from_utf8(data.split(|&c|c==0)
        .next().unwrap_or_default().to_vec()).unwrap_or_default().as_ref() {
            "Error incorrect challenge was entered" => Err(OnlyKeyError::WrongChallenge),
            "Error no key set in this slot" => Err(OnlyKeyError::NoKeySet(key.slot.clone())),
            "Error key not set as signature key" => Err(OnlyKeyError::NotASignatureKey(key.slot.clone())),
            "Error key not set as decryption key" => Err(OnlyKeyError::NotADecryptionKey(key.slot.clone())),
            "Error with RSA data to sign invalid size" => Err(OnlyKeyError::InvalidDataSize),
            "Error with RSA signing" => Err(OnlyKeyError::SignFailed),
            "Error with RSA data to decrypt invalid size" => Err(OnlyKeyError::InvalidDataSize),
            "Error with RSA decryption" => Err(OnlyKeyError::DecryptFailed),
            "Error ECC type incorrect" => Err(OnlyKeyError::InvalidEccType),
            s@"Error invalid key, key check failed" => Err(OnlyKeyError::Other(s.to_owned())),
            s@"invalid data, or data does not match key" => Err(OnlyKeyError::Other(s.to_owned())),
            s@"Error invalid data, or data does not match key" => Err(OnlyKeyError::Other(s.to_owned())),
            "Error generating RSA public N" => Err(OnlyKeyError::PublicKeyGenerationFailed),
            "Error you must set a PIN first on OnlyKey" => Err(OnlyKeyError::NotInitialized),
            "Error device locked" => Err(OnlyKeyError::Locked),
            "Error not in config mode, hold button 6 down for 5 sec" => Err(OnlyKeyError::NotInConfigMode),
            "No PIN set, You must set a PIN first" => Err(OnlyKeyError::NotInitialized),
            "Error invalid ECC slot" => Err(OnlyKeyError::WrongEccSlot),
            "Error no ECC Private Key set in this slot" => Err(OnlyKeyError::NoKeySet(key.slot.clone())),
            "Error invalid RSA slot" => Err(OnlyKeyError::WrongRsaSlot),
            "Error no RSA Private Key set in this slot" => Err(OnlyKeyError::NoKeySet(key.slot.clone())),
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