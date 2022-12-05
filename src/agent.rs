use std::{time::Duration, path::PathBuf, process::Command, sync::{Mutex, Arc}};

use log::{trace, debug, info, error, warn};
use anyhow::{Result, bail};
use thiserror::Error;
use num::FromPrimitive;
use num_derive::FromPrimitive;
use sha2::{Sha256, Digest};

use crate::{assuan::{AssuanClient, AssuanServer, AssuanCommand, AssuanResponse, self, ServerError, ClientError}, config::{KeyInfo, KeyType}, csexp::Sexp};

use crate::config::Settings;

use crate::onlykey::{OnlyKey, OnlyKeyError};

pub fn handle_client(mut client: AssuanClient, mut server: AssuanServer, my_agent: Arc<Mutex<MyAgent>>) -> Result<bool> {
    loop {
        trace!("[handle_client] Reading client");
        match client.recv()? {
            AssuanCommand::Bye => {
                info!("Client said 'BYE', disconnecting...");
                break;
            }
            AssuanCommand::Reset => {
                info!("Client asked for reset. Sending to agent.");
                my_agent.lock().unwrap().reset();
                server.send(AssuanCommand::Reset)?;
            },
            AssuanCommand::Command { command, parameters } => match command.as_ref() {
                "KILLAGENT" => {
                    info!("Client asked to kill the agent");
                    server.send(AssuanCommand::Command { command, parameters})?;
                    return Ok(true);
                }
                "HAVEKEY" => {
                    debug!("HAVEKEY command received: {:?}", parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut processed = false;
                    if my_agent.lock().unwrap().check_ready() {
                        if let Some(param) = parameters.as_ref().and_then(|param| String::from_utf8(param.clone()).ok()) {
                            if param.starts_with("--list") {
                                trace!("Client asked the list of known secret keys");
                                let keygrips = my_agent.lock().unwrap().get_known_keygrips();
                                if !keygrips.is_empty() {
                                    let keygrips: Vec<u8> = keygrips.iter().flat_map(|grip| hex::decode(grip).unwrap_or_else(|_|{
                                        error!("A keygrip is not hex encoded.");
                                        Vec::new()
                                    })).collect();
                                    client.send(crate::assuan::AssuanResponse::Data(keygrips))?;
                                }
                            } else {
                                trace!("Client asked for specific secret keys");
                                if param.split_ascii_whitespace().any(|grip| my_agent.lock().unwrap().have_key(grip)) {
                                    client.send_ok("")?;
                                    processed = true;
                                }
                            }
                        }
                    }
                    if !processed {
                        server.send(AssuanCommand::Command { command, parameters})?;
                    }
                }
                "KEYINFO" => {
                    debug!("KEYINFO command received: {:?}", parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut processed = false;
                    if my_agent.lock().unwrap().check_ready() {
                        if let Some(param) = parameters.as_ref().and_then(|param| String::from_utf8(param.clone()).ok()) {
                            let key_info_cmd = KeyInfoCommand::parse(param.split_ascii_whitespace());
                            if key_info_cmd.list {
                                todo!();
                            } else if key_info_cmd.ssh_list {
                                // Do nothing for now
                            } else if my_agent.lock().unwrap().get_known_keygrips().contains(&key_info_cmd.keygrip) {
                                let response = format!("{} T - - - C - - A", key_info_cmd.keygrip);
                                debug!("Sending '{}' to client", response);
                                if key_info_cmd.data {
                                    client.send(AssuanResponse::Data(response.into_bytes()))?;
                                } else {
                                    client.send(AssuanResponse::Processing {
                                        keyword: "KEYINFO".to_owned(), info: Some(response) })?;
                                }
                                client.send_ok("")?;
                                processed = true;
                            }
                        }
                    }
                    if !processed {
                        server.send(AssuanCommand::Command { command, parameters})?;
                    }
                },
                "SIGKEY" | "SETKEY" => {
                    debug!("{} command received: {:?}", command, parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut processed = false;
                    if let Some(keygrip) = parameters.as_ref().and_then(|param| String::from_utf8(param.clone()).ok()) {
                        let mut my_agent = my_agent.lock().unwrap();
                        if my_agent.select_key(&keygrip) && my_agent.check_ready() {
                            // We have the corresponding private key and the OnlyKey is ready to process things
                            // No need for gpg-agent to know about future operations
                            client.send_ok("")?;
                            processed = true;
                        }
                    }
                    if !processed {
                        server.send(AssuanCommand::Command { command, parameters})?;
                    }
                },
                "SETKEYDESC" => {
                    debug!("SETKEYDESC command received");
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    server.send(AssuanCommand::Command { command, parameters})?;
                    trace!("Key desc sent to server");
                }
                "SETHASH" => {
                    debug!("SETHASH command received: {:?}", parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut my_agent = my_agent.lock().unwrap();
                    if let Some(param) = parameters.as_ref().and_then(|param| String::from_utf8(param.clone()).ok()) {
                        let hash_data = HashData::parse(param.split_ascii_whitespace());
                        my_agent.data_to_sign = Some(hash_data);
                    }
                    // Send to gpg-agent anyway, in case we can't process the hash later
                    server.send(AssuanCommand::Command { command, parameters})?;
                }
                "PKSIGN" => {
                    debug!("PKSIGN command received: {:?}", parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut my_agent = my_agent.lock().unwrap();
                    let mut processed = false;
                    if my_agent.key.is_some() && my_agent.check_ready() {
                        if my_agent.data_to_sign.is_none() {
                            client.send(AssuanResponse::Inquire { keyword: "HASHVAL".to_owned(), parameters: None })?;
                        } else {
                            debug!("Signing data");
                            match my_agent.sign_data() {
                                Ok(sig) => {
                                    debug!("Sending signature");
                                    client.send(AssuanResponse::Data(sig.to_vec()))?;
                                    client.send_ok("")?;
                                },
                                Err(e) => {
                                    error!("Could not sign data: {}", e);

                                    let code = match e {
                                        AgentError::OnlyKeyError(OnlyKeyError::WrongChallenge) => {
                                            Some(GpgError::GPG_ERR_BAD_PIN)
                                        },
                                        AgentError::OnlyKeyError(OnlyKeyError::Timeout) => {
                                            Some(GpgError::GPG_ERR_TIMEOUT)
                                        }
                                        _ => {
                                            None
                                        }
                                    };
                                    if let Some(code) = code {
                                        client.send_err(
                                            &code.gpg_error().to_string(),
                                            Some(&format!("{} <{}>", code.as_string(), GpgErrorSource::default().as_string()))
                                        )?;
                                    } else {
                                        client.send_err(&GpgError::GPG_ERR_INTERNAL.gpg_error().to_string(), Some(&format!("Could not sign the data: {:?} <{}>", e, GpgErrorSource::default().as_string())))?;
                                    }
                                }
                            }
                        }
                        processed = true;
                    }
                    if !processed {
                        server.send(AssuanCommand::Command { command, parameters})?;
                    }
                }
                "PKDECRYPT" => {
                    debug!("PKDECRYPT command received: {:?}", parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    let mut my_agent = my_agent.lock().unwrap();
                    let mut processed = false;

                    /*server.send(AssuanCommand::Command { command: command.clone(), parameters: parameters.clone()})?;
                    my_agent.srf.lock().unwrap().push(ServerResponseFilter::Inquire);
                    my_agent.srf.lock().unwrap().push(ServerResponseFilter::Processing);*/

                    if my_agent.key.is_some() && my_agent.check_ready() {
                        client.send(AssuanResponse::Processing {
                            keyword: "INQUIRE_MAXLEN".to_owned(),
                            info: Some("4096".to_owned()) })?;
                        match client.inquire("CIPHERTEXT".to_owned(), None ) {
                            Ok(data) => {
                                //Got data to decrypt
                                //server.send_data(data.clone())?;
                                match my_agent.decrypt(data) {
                                    Ok(decrypted) => {
                                        debug!("Sending decrypted data");
                                        client.send(AssuanResponse::Data(decrypted.to_vec()))?;
                                        client.send_ok("")?;
                                    },
                                    Err(e) => {
                                        error!("Could not decrypt data: {}", e);
    
                                        let code = match e {
                                            AgentError::OnlyKeyError(OnlyKeyError::WrongChallenge) => {
                                                Some(GpgError::GPG_ERR_BAD_PIN)
                                            },
                                            AgentError::OnlyKeyError(OnlyKeyError::Timeout) => {
                                                Some(GpgError::GPG_ERR_TIMEOUT)
                                            }
                                            _ => {
                                                None
                                            }
                                        };
                                        if let Some(code) = code {
                                            client.send_err(
                                                &code.gpg_error().to_string(),
                                                Some(&format!("{} <{}>", code.as_string(), GpgErrorSource::default().as_string()))
                                            )?;
                                        } else {
                                            client.send_err(&GpgError::GPG_ERR_INTERNAL.gpg_error().to_string(), Some(&format!("Could not decrypt the data: {:?} <{}>", e, GpgErrorSource::default().as_string())))?;
                                        }
                                    }
                                }
                            },
                            Err(ClientError::Canceled) => {
                                warn!("Client canceled the decryption operation.");
                            }
                            Err(ClientError::UnexpectedCommand(cmd)) => {
                                warn!("Got unexepected command {:?} while processing decryption data", cmd);
                            }
                            Err(e) => {
                                bail!(e);
                            }
                        }
                        processed = true;
                    }
                    if !processed {
                        server.send(AssuanCommand::Command { command, parameters})?;
                    }
                }
                _ => {
                    debug!("Got command: Command {{{}, {:?}}} ", command, parameters);
                    if let Some(str) = parameters.as_ref().and_then(|data| String::from_utf8(data.clone()).ok()){
                        debug!("Parameter: {}", str);
                    }
                    
                    server.send(AssuanCommand::Command { command, parameters})?;
                }
            }
            cmd => {
                debug!("Got command: {:?}", cmd);
                server.send(cmd)?;
            },
        }
    }

    Ok(false)
}

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AgentError {
    #[error("No data to sign")]
    NoSignData,
    #[error("No key set")]
    NoKey,
    #[error("No OnlyKey connected")]
    OnlyKeyNotConnected,
    #[error("Invalid signature: length is {0}")]
    InvalidSignatureLength(usize),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    SettingsError(#[from] config::ConfigError),
    #[error("Connection to OnlyKey failed with {0}")]
    OnlyKeyConnectionFailed(OnlyKeyError),
    #[error(transparent)]
    OnlyKeyError(#[from] OnlyKeyError),
    #[error("Unknown error")]
    Other,
    #[error("Not Implemented")]
    NotImplemented,
}

// gpg error value = ((source & 127) << 24) |  (code & 65535)
// source = 8 bits value
// code = 16 bits value

#[allow(non_camel_case_types, dead_code)]
#[derive(Copy, Clone)]
pub enum GpgErrorSource {
    GPG_ERR_SOURCE_UNKNOWN = 0,
    GPG_ERR_SOURCE_GPGAGENT = 4,
    GPG_ERR_SOURCE_OK_AGENT = 18,
    GPG_ERR_SOURCE_ANY = 31,
}

impl GpgErrorSource {
    fn default() -> Self {
        GpgErrorSource::GPG_ERR_SOURCE_OK_AGENT
    }
    pub fn as_string(&self) -> String {
        match self {
            GpgErrorSource::GPG_ERR_SOURCE_UNKNOWN => "Unspecified source".to_owned(),
            GpgErrorSource::GPG_ERR_SOURCE_GPGAGENT => "GPG Agent".to_owned(),
            GpgErrorSource::GPG_ERR_SOURCE_ANY => "Any source".to_owned(),
            GpgErrorSource::GPG_ERR_SOURCE_OK_AGENT => "OnlyKey Agent".to_owned(),

        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum GpgError {
    GPG_ERR_TIMEOUT = 62,
    GPG_ERR_INTERNAL = 63,
    GPG_ERR_BAD_PIN = 87,
}

impl GpgError {
    pub fn gpg_error(&self) -> u32 {
        self.gpg_error_with_source(GpgErrorSource::default())
    }

    pub fn gpg_error_with_source(&self, source: GpgErrorSource) -> u32 {
        ((source as u32) << 24) | (*self as u32)
    }

    pub fn as_string(&self) -> String {
        match self {
            GpgError::GPG_ERR_BAD_PIN => "A bad pin has been entered".to_owned(),
            GpgError::GPG_ERR_TIMEOUT => "Timeout".to_owned(),
            GpgError::GPG_ERR_INTERNAL => "Internal Error".to_owned(),
        }
    }
}

pub struct MyAgent {
    onlykey: Option<Arc<Mutex<OnlyKey>>>,
    pub server: Option<AssuanServer>,
    pub config_file: PathBuf,
    pub settings: Settings,
    pub srf: Arc<Mutex<Vec<ServerResponseFilter>>>,
    key: Option<KeyInfo>,
    data_to_sign: Option<HashData>,
}

impl MyAgent {
    pub fn new(config_file: PathBuf, settings: Settings, srf: Arc<Mutex<Vec<ServerResponseFilter>>>) -> Result<Self, AgentError> {
        let mut agent = MyAgent { onlykey: None, server: None, config_file, settings, key: None, srf, data_to_sign: None};

        agent.try_connect_device()?;

        Ok(agent)
    }

    pub fn reset(&mut self) {
        self.key = None;
        self.data_to_sign = None;
        self.srf.lock().unwrap().clear();
    }

    /// Try to connect to an OnlyKey.
    /// 
    /// # Error
    /// Return [`AgentError::OnlyKeyConnectionFailed`] if the connection to a device failed.
    fn try_connect_device(&mut self) -> Result<(), AgentError> {
        self.onlykey = OnlyKey::try_connection().map_err(AgentError::OnlyKeyConnectionFailed)?;
        Ok(())
    }

    /// Check if the agent is ready to handle operations requiering the OnlyKey
    pub fn check_ready(&mut self) -> bool {
        debug!("Checking if agent is ready to handle things");

        // If the previously registerd OnlyKey has been disconnected, we will try to reconnect
        if let Some(ok) = &self.onlykey {
            if !ok.lock().unwrap().connected {
                self.onlykey = None;
            }
        }
        match &mut self.onlykey {
            Some(ok) => {
                let ok = ok.lock().unwrap();
                //ok.set_time()?;
                if ok.read_timeout(Some(Duration::ZERO)).is_err() {
                    warn!("OnlyKey has been removed");
                    drop(ok);
                    self.onlykey = None;
                    false
                } else {
                    debug!("The plugged key is {}", if ok.unlocked {"unlocked"} else {"locked"});
                    ok.unlocked
                }
            },
            None => {
                debug!("No key plugged on last check. Checking again.");
                if let Err(e) =  self.try_connect_device() {
                    error!("Problem connecting to device: {:?}", e);
                    return false;
                }
                if let Some(ok) = &self.onlykey {
                    let ok = ok.lock().unwrap();
                    debug!("The plugged key is {}", if ok.unlocked {"unlocked"} else {"locked"});
                    return ok.unlocked;
                } else {
                    debug!("No key plugged");
                }
                false
            },
        }
    }

    pub fn get_known_keygrips(&self) -> Vec<String> {
        self.settings.keyinfo.iter().map(|info| info.keygrip()).collect()
    }

    pub fn have_key(&self, keygrip: &str) -> bool {
        self.settings.keyinfo.iter().any(|info| info.keygrip() == keygrip)
    }

    /// Select the key for future operations.
    /// Returns `true` if the key exists, `false` otherwise.
    /// 
    pub fn select_key(&mut self, keygrip: &str) -> bool {
        if let Some(info) = self.settings.keyinfo.iter().find(|info| info.keygrip() == keygrip) {
            self.key = Some(info.clone());
            return true;
        }
        false
    }

    /// Sign the `data_to_sign` with the `sign_key`.
    /// Returns an SPKI-like S-expression containing the signature:
    /// ```ignore
    /// (sig-val
    ///     (<algo>
    ///         (<param_name1> <mpi>)
    ///         (<param_namen> <mpi>)))
    /// ```
    pub fn sign_data(&mut self) -> Result<Sexp, AgentError> {
        if let Some(data) = self.data_to_sign.clone() {
            if let Some(sign_key) = self.key.clone() {
                if let Some(ok) = self.onlykey.clone() {
                    debug!("Data to sign: {:?}", self.data_to_sign);
                    self.display_challenge(&data.data)?;

                    let signature = ok.lock().unwrap().sign(&data.data, &sign_key)?;
                    match sign_key.r#type() {
                        Ok(KeyType::Ecc(_)) => {
                            if signature.len() != 64 {
                                error!("Signature length is {}, expected 64", signature.len());
                                return Err(AgentError::InvalidSignatureLength(signature.len()));
                            }
                        },
                        Ok(KeyType::Rsa(size)) => {
                            if signature.len() != size/8 {
                                error!("Signature length is {}, expected {}", signature.len(), size/8);
                                return Err(AgentError::InvalidSignatureLength(signature.len()));
                            }
                        }
                        Err(e) => {
                            error!("Error while getting the type of the key: {:?}", e);
                            return Err(AgentError::Other);
                        }
                    }

                    let sexp = match sign_key.r#type() {
                        Ok(KeyType::Ecc(_)) => {
                            Sexp::List(vec![
                                Sexp::Atom(b"sig-val".to_vec()),
                                Sexp::List(vec![
                                    Sexp::Atom(b"ecdsa".to_vec()),
                                    Sexp::List(vec![
                                        Sexp::Atom(b"r".to_vec()),
                                        Sexp::Atom(signature[..32].to_vec()),
                                    ]),
                                    Sexp::List(vec![
                                        Sexp::Atom(b"s".to_vec()),
                                        Sexp::Atom(signature[32..].to_vec()),
                                    ]),
                                ]),
                            ])
                        },
                        Ok(KeyType::Rsa(_)) => {
                            Sexp::List(vec![
                                Sexp::Atom(b"sig-val".to_vec()),
                                Sexp::List(vec![
                                    Sexp::Atom(b"rsa".to_vec()),
                                    Sexp::List(vec![
                                        Sexp::Atom(b"s".to_vec()),
                                        Sexp::Atom(signature.to_vec()),
                                    ]),
                                ]),
                            ])
                        },
                        Err(e) => {
                            error!("Error while getting the type of the key: {:?}", e);
                            return Err(AgentError::Other);
                        }
                    };

                    debug!("Signature S-Exp: {:?}", sexp);

                    Ok(sexp)
                } else {
                    Err(AgentError::OnlyKeyNotConnected)
                }
            } else {
                Err(AgentError::NoKey)
            }
        } else {
            Err(AgentError::NoSignData)
        }
    }

    pub fn decrypt(&mut self, data: Vec<u8>) -> Result<Sexp, AgentError> {
        if let Some(key) = self.key.clone() {
            if let Some(ok) = self.onlykey.clone() {
                debug!("Data to decrypt: {:?}", data);
                let ciphertext = match key.r#type() {
                    Ok(KeyType::Ecc(_)) => {
                        parse_ecdh(&data).map_err(|_| AgentError::Other)?
                    },
                    Ok(KeyType::Rsa(_)) => {
                        parse_rsa(&data).map_err(|_| AgentError::Other)?
                    },
                    Err(e) => {
                        error!("Error while getting the type of the key: {:?}", e);
                        return Err(AgentError::Other);
                    }
                };
                self.display_challenge(&ciphertext)?;

                let plaintext = ok.lock().unwrap().decrypt(&ciphertext, &key)?;

                let sexp = Sexp::List(vec![
                    Sexp::Atom(b"value".to_vec()),
                    Sexp::Atom(plaintext),
                ]);

                debug!("Decrypted S-Exp: {:?}", sexp);

                Ok(sexp)
            } else {
                Err(AgentError::OnlyKeyNotConnected)
            }
        } else {
            Err(AgentError::NoKey)
        }
    }

    fn display_challenge(&mut self, data: &[u8]) -> Result<(), AgentError> {
        // Compute challenge
        let h1 = Sha256::new()
        .chain_update(data)
        .finalize();
        let (b1, b2, b3) = (OnlyKey::get_button(h1[0]), OnlyKey::get_button(h1[15]), OnlyKey::get_button(h1[31]));
        let challenge_str = format!("Enter the 3 digit challenge code on OnlyKey to authorize operation:\n{} {} {}", b1, b2, b3);
        if self.settings.challenge {
            info!("{}", challenge_str);
            if let Some(server) = &mut self.server {
                // Display challenge with original gpg-agent
                self.srf.lock().unwrap().push(ServerResponseFilter::OkOrErr);
                self.srf.lock().unwrap().push(ServerResponseFilter::CancelInquire);
                let challenge_str = assuan::encode_percent(&challenge_str);
                server.send(AssuanCommand::Command { command: "GET_CONFIRMATION".to_owned(), parameters: Some(challenge_str) }).map_err(|e| {
                    if let ServerError::IOError(io) = e {
                        return AgentError::IOError(io);
                    }
                    AgentError::Other
                })?;
            }
        }
        Ok(())
    }
}

pub fn get_homedir() -> Result<PathBuf> {
    let output = Command::new("gpgconf")
        .args(["--list-dirs", "homedir"])
        .output()?;
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}

/// Parse an S-Expression containing ECDH parts and return the remote public key
pub fn parse_ecdh(s: &[u8]) -> Result<Vec<u8>, ()> {
    debug!("Parsing ecdh data");
    match Sexp::parse(s) {
        Ok(exp) => {
            debug!("Sexp parsed successfully: {:?}", exp);
            if let Sexp::List(exps) = exp {
                if exps.get( 0) == Some(&Sexp::Atom(b"enc-val".to_vec())) {
                    if let Some(Sexp::List(exps)) = exps.get(1) {
                        if exps.get(0) == Some(&Sexp::Atom(b"ecdh".to_vec())) {
                            if let Some(Sexp::List(e)) = exps.get(2) {
                                if e.get(0) == Some(&Sexp::Atom(b"e".to_vec())) {
                                    if let Some(Sexp::Atom(e)) = e.get(1) {
                                        return Ok(e.to_vec());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(())
        },
        Err(e) => {
            warn!("Could not parse Sexp: {:?}", e);
            Err(())
        }
    }
}

/// Parse an S-Expression containing RSA parts and return the RSA-encoded data
pub fn parse_rsa(s: &[u8]) -> Result<Vec<u8>, ()> {
    debug!("Parsing rsa data");
    match Sexp::parse(s) {
        Ok(exp) => {
            debug!("Sexp parsed successfully: {:?}", exp);
            if let Sexp::List(exps) = exp {
                if exps.get( 0) == Some(&Sexp::Atom(b"enc-val".to_vec())) {
                    if let Some(Sexp::List(exps)) = exps.get(1) {
                        if exps.get(0) == Some(&Sexp::Atom(b"rsa".to_vec())) {
                            if let Some(Sexp::List(a)) = exps.get(1) {
                                if a.get(0) == Some(&Sexp::Atom(b"a".to_vec())) {
                                    if let Some(Sexp::Atom(a)) = a.get(1) {
                                        return Ok(a.to_vec());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(())
        },
        Err(e) => {
            warn!("Could not parse Sexp: {:?}", e);
            Err(())
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct KeyInfoCommand {
    list: bool,
    ssh_list: bool,
    data: bool,
    with_ssh: bool,
    ssh_fpr: Option<Option<String>>,
    keygrip: String,
}

impl KeyInfoCommand {
    fn parse<I>(itr: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut list = false;
        let mut ssh_list = false;
        let mut data = false;
        let mut with_ssh = false;
        let mut ssh_fpr: Option<Option<String>> = None;
        let mut keygrip = String::new();
        for item in itr {
            match item.as_ref() {
                "--list" => list = true,
                "--ssh-list" => ssh_list = true,
                "--data" => data = true,
                "--with-ssh" => with_ssh = true,
                "--ssh-fpr" => ssh_fpr = Some(None),
                item => {
                    if let Some(fpr) = item.strip_prefix("--ssh-fpr=") {
                        ssh_fpr = Some(Some(fpr.to_owned()));
                    } else {
                        keygrip = item.to_owned();
                    }
                }
            }
        }
        KeyInfoCommand {list, ssh_list, data, with_ssh, ssh_fpr, keygrip}
    }
}

#[allow(dead_code)]
#[derive(Debug)]
#[derive(Clone)]
struct HashData {
    algo: Option<Hash>,
    inquire: bool,
    pss: bool,
    data: Vec<u8>,
}

impl HashData {
    fn parse<I>(itr: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut algo = None;
        let mut inquire = false;
        let mut pss = false;
        let mut data = Vec::new();
        let mut itr = itr.into_iter();
        while let Some(item) = itr.next() {
            match item.as_ref() {
                "--inquire" => inquire = true,
                "--pss" => pss = true,
                item => {
                    if let Some(hash) = item.strip_prefix("--hash=") {
                        algo = match hash {
                            "sha1" => Some(Hash::SHA1),
                            "sha224" => Some(Hash::SHA224),
                            "sha256" => Some(Hash::SHA256),
                            "sha384" => Some(Hash::SHA384),
                            "sha512" => Some(Hash::SHA512),
                            "rmd160" => Some(Hash::RMD160),
                            "md5" => Some(Hash::MD5),
                            "tls-md5sha1" => Some(Hash::TlsMd5Sha1),
                            _ => None,
                        };
                    } else if let Some(next) = itr.next() {
                        
                        algo = FromPrimitive::from_i16(item.parse().unwrap_or(0));
                        data = hex::decode(next.as_ref()).unwrap_or_default();
                    } else {
                        data = hex::decode(item).unwrap_or_default();
                    }
                }
            }
        }
        Self {algo, inquire, pss, data}
    }
}

#[allow(dead_code)]
pub enum ServerResponseFilter {
    CancelInquire,
    OkOrErr,
    Processing,
    Inquire,
}

#[derive(Debug)]
#[derive(FromPrimitive, Clone)]
enum Hash {
    MD5           = 1,
    SHA1          = 2,
    RMD160        = 3,
    MD2           = 5,
    Tiger         = 6,
    Haval         = 7,
    SHA256        = 8,
    SHA384        = 9,
    SHA512        = 10,
    SHA224        = 11,
    MD4           = 301,
    CRC32         = 302,
    Crc32Rfc1510  = 303,
    Crc24Rfc2440  = 304,
    Whirlpool     = 305,
    TIGER1        = 306, /* TIGER fixed.  */
    TIGER2        = 307, /* TIGER2 variant.   */
    GOSTR3411_94  = 308, /* GOST R 34.11-94.  */
    STRIBOG256    = 309, /* GOST R 34.11-2012, 256 bit.  */
    STRIBOG512    = 310, /* GOST R 34.11-2012, 512 bit.  */
    Gostr3411Cp   = 311, /* GOST R 34.11-94 with CryptoPro-A S-Box.  */
    SHA3_224      = 312,
    SHA3_256      = 313,
    SHA3_384      = 314,
    SHA3_512      = 315,
    SHAKE128      = 316,
    SHAKE256      = 317,
    Blake2b512    = 318,
    Blake2b384    = 319,
    Blake2b256    = 320,
    Blake2b160    = 321,
    Blake2s256    = 322,
    Blake2s224    = 323,
    Blake2s160    = 324,
    Blake2s128    = 325,
    SM3           = 326,
    SHA512_256    = 327,
    SHA512_224    = 328,

    TlsMd5Sha1,
}