use std::{net::Shutdown, path::{PathBuf, Path}, io::{Write, Read, BufWriter, BufReader, BufRead}, process::{Command, Child, Stdio, ChildStdout, ChildStdin}, sync::{Arc, Mutex}};

use log::{info, trace, error, debug};
use thiserror::Error;

mod stream;
use stream::Stream;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::net::{TcpListener};
#[cfg(windows)]
use rand::{thread_rng, Fill};
#[cfg(windows)]
use std::fs::File;

#[cfg(unix)]
use std::os::unix::net::{UnixListener};

const LINE_LENGHT: usize = 1000;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Operation canceled")]
    Canceled,
    #[error("Wrong nonce")]
    #[cfg(windows)]
    WrongNonce,
    #[error("Got EOF while reading")]
    Eof,
    #[error("Invalid command {0:?}")]
    InvalidCommand(Vec<u8>),
    #[error("Unexpected command {0:?}")]
    UnexpectedCommand(AssuanCommand),
    #[error("Keyword shall start with a letter or an underscore")]
    InvalidKeyword,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Got EOF while reading")]
    Eof,
    #[error("Invalid command {0:?}")]
    InvalidCommand(Vec<u8>),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[cfg(windows)]
pub struct AssuanListener {
    tcp_listener: TcpListener,
    _socket_file: PathBuf,
    nonce: [u8; 16],
}

#[cfg(windows)]
impl AssuanListener {
    pub fn new() -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        info!("Listening on port {}", listener.local_addr()?.port());

        let agent_socket = get_socket_file_path()?;
        info!("Socket file is {:?}", agent_socket);

        let mut nonce = [0u8; 16];
        let mut rng = thread_rng();
        nonce.try_fill(&mut rng)?;

        let mut file = File::create(&agent_socket)?;
        file.write_all(format!("{}\n", listener.local_addr()?.port()).as_bytes())?;
        file.write_all(&nonce)?;

        Ok(AssuanListener { tcp_listener: listener, _socket_file: agent_socket, nonce})
    }

    pub fn accept(&self) -> Result<AssuanClient, std::io::Error> {
        let (socket, addr) = self.tcp_listener.accept()?;
        info!("Connection with {}", addr);
        Ok(AssuanClient { stream: Stream {stream: socket}, nonce: self.nonce })
    }
}

#[cfg(unix)]
pub struct AssuanListener {
    listener: UnixListener,
    socket_file: PathBuf,
}

#[cfg(unix)]
impl AssuanListener {
    pub fn new() -> Result<Self, std::io::Error> {
        let agent_socket = get_socket_file_path()?;
        info!("Socket file is {:?}", agent_socket);

        // TODO: Follow link in socket if any

        let listener = UnixListener::bind(&agent_socket)?;

        debug!("Unix socket bound");

        Ok(AssuanListener { listener, socket_file: agent_socket})
    }

    pub fn accept(&self) -> Result<AssuanClient, std::io::Error> {
        let (stream, _) = self.listener.accept()?;
        info!("New connection");
        Ok(AssuanClient { stream: Stream {stream} })
    }
}

#[cfg(unix)]
impl Drop for AssuanListener {
    fn drop(&mut self) {
        std::fs::remove_file(&self.socket_file).unwrap();
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum AssuanCommand {
    Bye,
    Reset,
    End,
    Help,
    Quit,
    Option {
        name: String,
        value: Option<String>,
    },
    Cancel,
    Auth,
    Command {
        command: String,
        parameters: Option<Vec<u8>>,
    },
    Data(Vec<u8>),
    Nop,
}

#[allow(dead_code)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
pub enum AssuanResponse {
    /// Request is successful
    Ok(Option<String>),
    /// Request can not be fulfilled
    Err {
        /// Error code as defined by [libgpg-error](https://github.com/gpg/libgpg-error/blob/master/doc/errorref.txt)
        code: String,
        /// Human-readable description
        description: Option<String>,
    },
    End,
    /// Request is still under processing
    Processing {
        /// Keyword
        keyword: String,
        /// Status information
        info: Option<String>,
    },
    /// Comment that will be ignored by receiver
    Comment(String),
    /// Raw data to send
    Data(Vec<u8>),
    /// Server needs further information
    Inquire {
        keyword: String,
        parameters: Option<String>,
    },
    /// We don't know this response, keep it as-is
    Unknown(Vec<u8>),
}

pub struct AssuanClient {
    stream: Stream,
    //reader: Arc<Mutex<BufReader<Stream>>>,
    //writer: Arc<Mutex<BufWriter<Stream>>>,
    #[cfg(windows)]
    nonce: [u8; 16],
}

impl AssuanClient {
    /// Connect the client.
    /// 
    /// # Errors
    /// Return [`ClientError::IOError`] if the read operation is unseccessful or 
    /// a [`ClientError::WrongNonce`] if the provided nonce doesn't match.
    pub fn connect(&mut self) -> Result<(), ClientError> {
        self.validate()?;
        self.send_ok("pleased to meet you")
    }

    pub fn close(&mut self) -> Result<(), ClientError> {
        self.stream.flush()?;
        Ok(self.stream.shutdown(Shutdown::Both)?)
    }

    /// Validate the client by checking the nonce.
    /// 
    /// # Errors
    /// Return [`ClientError::WrongNonce`] if the provided nonce doesn't match or
    /// [`ClientError::IOError`] if the underlying operation failed.
    #[cfg(windows)]
    fn validate(&mut self) -> Result<(), ClientError> {
        let mut nonce: [u8; 16] = [0; 16];
        self.stream.read_exact(&mut nonce)?;
        if nonce != self.nonce {
            return Err(ClientError::WrongNonce);
        }
        Ok(())
    }

    /// Placeholder for Windows feature. Don't do anything on Unix (return `Ok(())`)
    #[cfg(unix)]
    fn validate(&mut self) -> Result<(), ClientError> {
        Ok(())
    }

    /// Receive a command from the client.
    /// 
    /// # Errors
    /// Return [`ClientError::InvalidCommand(Vec<u8>)`] if the read command is not a valid UTF8
    /// string or
    /// [`ClientError::IOError`] if the underlying operation failed.
    pub fn recv(&mut self) -> Result<AssuanCommand, ClientError> {
        let mut buf = vec![0u8; LINE_LENGHT];
        let mut num = 0;
        let mut last_byte = 0u8;
        trace!("Client reading");
        while num < LINE_LENGHT && last_byte != b'\n' {
            num += self.stream.read(&mut buf[num..])?;
            if num == 0 {
                return Err(ClientError::Eof);
            }
            last_byte = buf[num-1];
        }
        if last_byte == b'\n' {
            num -= 1;
        }
        trace!("Read: {:x?}", &buf[..num]);
        if let Ok(s) = String::from_utf8(buf[..num].to_vec()) {
            trace!("String: {}", s);
        }

        let command_end = buf.iter().position(|b| *b == b' ').unwrap_or(num);

        let (command, parameters) = buf[..num].split_at(command_end);

        let command = String::from_utf8(command.to_vec()).map_err(|_| ClientError::InvalidCommand(buf.clone()))?;
        // Remove space character at begining
        let parameters = if parameters.is_empty() {parameters} else {&parameters[1..]}; 

        match command.as_str() {
            "BYE" => {
                self.close()?;
                Ok(AssuanCommand::Bye)
            },
            "RESET" => {
                Ok(AssuanCommand::Reset)
            },
            "END" => {
                // TODO
                Ok(AssuanCommand::End)
            },
            "NOP" => {
                self.send_ok("")?;
                Ok(AssuanCommand::Nop)
            },
            "D" => {
                let data = decode_percent(parameters);
                Ok(AssuanCommand::Data(data))
            }
            _ => {
                let param = if parameters.is_empty() {None} else {Some(parameters.to_vec())};
                Ok(AssuanCommand::Command { command, parameters: param })
            }
        }
    }

    /// Send a response to the client.
    /// 
    /// # Errors
    /// Return [`ClientError::InvalidKeyword`] if a provided keyword doesn't start with a letter or
    /// an underscore or
    /// [`ClientError::IOError`] if the underlying operation failed.
    pub fn send(&mut self, data: AssuanResponse) -> Result<(), ClientError> {
        trace!("Sending response {:?}", data);
        match data {
            AssuanResponse::Ok(info) => {
                let mut buf: Vec<u8> = Vec::from(b"OK".as_slice());
                if let Some(info) = info {
                    buf.extend_from_slice(b" ".as_slice());
                    buf.extend_from_slice(info.as_bytes());
                }
                buf = validate_line(buf);
                buf.push(b'\n');
                self.stream.write_all(&buf)?;
            },
            AssuanResponse::Err { code, description } => {
                let mut buf: Vec<u8> = Vec::from(b"ERR ".as_slice());
                buf.extend_from_slice(code.as_bytes());
                if let Some(description) = description {
                    buf.extend_from_slice(b" ".as_slice());
                    buf.extend_from_slice(description.as_bytes());
                }
                buf = validate_line(buf);
                buf.push(b'\n');
                self.stream.write_all(&buf)?;
            },
            AssuanResponse::End => {
                let mut buf: Vec<u8> = Vec::from(b"END".as_slice());
                buf = validate_line(buf);
                buf.push(b'\n');
                self.stream.write_all(&buf)?;
            },
            AssuanResponse::Processing { keyword, info } => {
                if !keyword.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                    return Err(ClientError::InvalidKeyword);
                }
                let mut buf: Vec<u8> = Vec::from(b"S ".as_slice());
                buf.extend_from_slice(keyword.as_bytes());
                if let Some(info) = info {
                    buf.extend_from_slice(b" ".as_slice());
                    buf.extend_from_slice(info.as_bytes());
                }
                buf = validate_line(buf);
                buf.push(b'\n');
                self.stream.write_all(&buf)?;
            },
            AssuanResponse::Comment(text) => {
                for line in text.lines() {
                    let mut buf: Vec<u8> = Vec::from(b"# ".as_slice());
                    buf.extend_from_slice(line.as_bytes());
                    buf = validate_line(buf);
                    buf.push(b'\n');
                    self.stream.write_all(&buf)?;
                }
            },
            AssuanResponse::Data(mut data) => {
                data = data.iter().flat_map(|&b| {
                    if b == b'%' || b == b'\n' || b == b'\r' {
                        return format!("%{:02X}", b).as_bytes().to_vec();
                    }
                    vec![b]
                }).collect();

                for chunck in data.chunks(LINE_LENGHT - 3) {
                    let mut buf: Vec<u8> = Vec::from(b"D ".as_slice());
                    buf.extend_from_slice(chunck);
                    buf = validate_line(buf);
                    buf.push(b'\n');
                    self.stream.write_all(&buf)?;
                }
            },
            AssuanResponse::Inquire { keyword, parameters } => {
                if !keyword.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                    return Err(ClientError::InvalidKeyword);
                }
                let mut buf: Vec<u8> = Vec::from(b"INQUIRE ".as_slice());
                buf.extend_from_slice(keyword.as_bytes());
                if let Some(parameters) = parameters {
                    buf.extend_from_slice(b" ".as_slice());
                    buf.extend_from_slice(parameters.as_bytes());
                }
                buf = validate_line(buf);
                buf.push(b'\n');
                self.stream.write_all(&buf)?;
            },
            AssuanResponse::Unknown(mut data) => {
                data = validate_line(data);
                data.push(b'\n');
                self.stream.write_all(&data)?;
            }
        }
        Ok(())
    }

    /// Send OK to the client.
    /// 
    /// # Errors
    /// Return [`ClientError::InvalidKeyword`] if a provided keyword doesn't start with a letter or
    /// an underscore or
    /// [`ClientError::IOError`] if the underlying operation failed.
    pub fn send_ok(&mut self, info: &str) -> Result<(), ClientError> {
        self.send(AssuanResponse::Ok(if info.is_empty() {None} else {Some(info.to_owned())}))
    }

    /// Send ERR to the client.
    /// 
    /// # Errors
    /// Return [`ClientError::InvalidKeyword`] if a provided keyword doesn't start with a letter or
    /// an underscore or
    /// [`ClientError::IOError`] if the underlying operation failed.
    pub fn send_err(&mut self, code: &str, desc: Option<&str>) -> Result<(), ClientError> {
        self.send(AssuanResponse::Err{code: code.to_owned(), description: desc.map(String::from)})
    }

    pub fn inquire(&mut self, keyword: String, parameters: Option<String>) -> Result<Vec<u8>, ClientError> {
        self.send(AssuanResponse::Inquire { keyword, parameters })?;
        let mut data = Vec::new();
        loop {
            match self.recv()? {
                AssuanCommand::Data(mut d) => {
                    data.append(&mut d);
                }
                AssuanCommand::End => {
                    return Ok(data);
                }
                AssuanCommand::Cancel => {
                    return Err(ClientError::Canceled);
                }
                cmd => return Err(ClientError::UnexpectedCommand(cmd)),
            }
        }
    }
}

impl Clone for AssuanClient {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.try_clone().unwrap(),
            #[cfg(windows)]
            nonce: self.nonce
        }
    }
}
pub struct AssuanServer {
    pub agent: Arc<Mutex<Child>>,
    reader: Arc<Mutex<BufReader<ChildStdout>>>,
    writer: Arc<Mutex<BufWriter<ChildStdin>>>,
}

impl AssuanServer {
    /// Connect to the original `gpg-agent`.
    /// 
    /// # Panic
    /// Panics if the homedir gotten from `gpgconf` cannot be used by the OS.
    pub fn new(homedir: Option<&Path>, use_std_socket: bool, agent_path: Option<&Path>) -> Result<Self, ServerError> {
        // Start gpg-agent as a server.
        // Communication will be done via standard input/output.
        let orig_agent = match agent_path {
            Some(path) => path.to_owned(),
            None => get_original_agent()?,
        };

        let mut command = Command::new(orig_agent);
        if let Some(homedir) = homedir {
            command.args(["--homedir", homedir.as_os_str().to_str().expect("Cannot convert homedir path to os path")]);
        }
        if use_std_socket {
            command.arg("--use-standard-socket");
        }
        command.arg("--server");
        command.arg("--no-detach");
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());

        #[cfg(windows)]
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        info!("Spawning {:?} {:?}", command.get_program(), command.get_args());

        let mut agent = command.spawn()?;
        let stdout = agent.stdout.take().unwrap();
        let stdin = agent.stdin.take().unwrap();

        Ok(AssuanServer {agent: Arc::new(Mutex::new(agent)), reader: Arc::new(Mutex::new(BufReader::new(stdout))), writer: Arc::new(Mutex::new(BufWriter::new(stdin)))})

    }

    pub fn connect(&mut self) -> Result<(), ServerError> {
        match self.recv() {
            Ok(AssuanResponse::Ok(msg)) => {
                trace!("On connect received {}", msg.unwrap_or_default());
                Ok(())
            }
            other => {
                error!("Connection to server failed: expected OK, got {:?}", other);
                Err(ServerError::ConnectionFailed)
            },
        }
    }

    pub fn close(&mut self) -> Result<(), ServerError> {
        self.send(AssuanCommand::Bye)?;
        self.writer.lock().unwrap().flush()?;
        info!("Waiting for agent to close...");
        self.agent.lock().unwrap().wait()?;

        Ok(())
    }

    /// Receive a response from the server.
    /// 
    /// # Errors
    /// Return [`ServerError::Eof`] if the read returned nothing or
    /// [`ServerError::InvalidCommand(Vec<u8>)`] if the read command is not a valid UTF8 string or
    /// [`ServerError::IOError`] if the underlying operation failed.
    pub fn recv(&mut self) -> Result<AssuanResponse, ServerError> {
        let mut buf = Vec::<u8>::new();
        trace!("Server reader locking");
        {
            let mut reader = self.reader.lock().unwrap();
            reader.read_until(b'\n', &mut buf)?;
        }
        if buf.is_empty() {
            error!("Got EOF from server");
            return Err(ServerError::Eof);
        }

        if let Some(b'\n') = buf.last() {
            buf.pop();
        }

        trace!("Read: {:x?}", buf);
        if let Ok(s) = String::from_utf8(buf.clone()) {
            trace!("String: {}", s);
        }

        let command_end = buf.iter().position(|b| *b == b' ').unwrap_or(buf.len());

        let (command, parameters) = buf.split_at(command_end);

        let command = String::from_utf8(command.to_vec()).map_err(|_| ServerError::InvalidCommand(buf.clone()))?;
        // Remove space character at begining
        let parameters = if parameters.is_empty() {parameters} else {&parameters[1..]}; 

        match command.as_str() {
            "OK" => {
                let param = String::from_utf8(parameters.to_vec()).unwrap_or_default();
                Ok(AssuanResponse::Ok(if param.is_empty() {None} else {Some(param)}))
            },
            "ERR" => {
                let code_end = parameters.iter().position(|b| *b == b' ').unwrap_or(parameters.len());
                let code = String::from_utf8(parameters[..code_end].to_vec()).unwrap_or_default();
                let description = if code_end == parameters.len() {
                    None
                } else {
                    Some(String::from_utf8(parameters[code_end+1..].to_vec()).unwrap_or_default())
                };
                
                Ok(AssuanResponse::Err { code, description })
            }
            "D" => {
                let data = decode_percent(parameters);
                Ok(AssuanResponse::Data(data))
            }
            "S" => {
                let keyword_end = parameters.iter().position(|b| *b == b' ').unwrap_or(parameters.len());
                let keyword = String::from_utf8(parameters[..keyword_end].to_vec()).unwrap_or_default();
                let info = if keyword_end == parameters.len() {
                    None
                } else {
                    Some(String::from_utf8(parameters[keyword_end+1..].to_vec()).unwrap_or_default())
                };
                Ok(AssuanResponse::Processing { keyword, info })
            }
            "INQUIRE" => {
                let keyword_end = parameters.iter().position(|b| *b == b' ').unwrap_or(parameters.len());
                let keyword = String::from_utf8(parameters[..keyword_end].to_vec()).unwrap_or_default();
                let parameters = if keyword_end == parameters.len() {
                    None
                } else {
                    Some(String::from_utf8(parameters[keyword_end+1..].to_vec()).unwrap_or_default())
                };
                Ok(AssuanResponse::Inquire { keyword, parameters })
            }
            _ => {
                Ok(AssuanResponse::Unknown(buf))
            }
        }
    }

    /// Send a command to the server.
    /// 
    /// # Errors
    /// Return [`ServerError::IOError`] if the underlying operation failed.
    pub fn send(&mut self, data: AssuanCommand) -> Result<(), ServerError> {
        debug!("Sending command {:?} to server", data);
        let mut writer = self.writer.lock().unwrap();
        match data {
            AssuanCommand::Bye => {
                writer.write_all(b"BYE\n")?;
            },
            AssuanCommand::Reset => {
                writer.write_all(b"RESET\n")?;
            },
            AssuanCommand::End => {
                writer.write_all(b"END\n")?;
            },
            AssuanCommand::Help => {
                writer.write_all(b"HELP\n")?;
            },
            AssuanCommand::Command { command, parameters } => {
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(command.as_bytes());
                if let Some(param) = parameters {
                    buf.push(b' ');
                    buf.extend(param);
                }
                buf = validate_line(buf);
                buf.push(b'\n');
                writer.write_all(&buf)?;
            },
            AssuanCommand::Nop => {
                writer.write_all(b"NOP\n")?;
            },
            AssuanCommand::Quit => {
                writer.write_all(b"QUIT\n")?;
            },
            AssuanCommand::Option { name, value } => {
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(b"OPTION ");
                buf.extend_from_slice(name.as_bytes());
                if let Some(value) = value {
                    buf.extend_from_slice(b"=");
                    buf.extend_from_slice(value.as_bytes());
                }
                buf = validate_line(buf);
                buf.push(b'\n');

                writer.write_all(&buf)?;
            },
            AssuanCommand::Cancel => {
                writer.write_all(b"CAN\n")?;
            },
            AssuanCommand::Auth => {
                writer.write_all(b"AUTH\n")?;
            },
            AssuanCommand::Data(mut data) => {
                data = data.iter().flat_map(|&b| {
                    if b == b'%' || b == b'\n' || b == b'\r' {
                        return format!("%{:02X}", b).as_bytes().to_vec();
                    }
                    vec![b]
                }).collect();

                for chunck in data.chunks(LINE_LENGHT - 3) {
                    let mut buf: Vec<u8> = Vec::from(b"D ".as_slice());
                    buf.extend_from_slice(chunck);
                    buf = validate_line(buf);
                    buf.push(b'\n');
                    writer.write_all(&buf)?;
                }
            },
        }
        writer.flush()?;
        Ok(())
    }

    #[allow(dead_code)]
    /// Send provided data followed by an END message.
    pub fn send_data(&mut self, data: Vec<u8>) -> Result<(), ServerError> {
        self.send(AssuanCommand::Data(data))?;
        self.send(AssuanCommand::End)
    }
}

impl Clone for AssuanServer {
    fn clone(&self) -> Self {
        Self { agent: self.agent.clone(), reader: self.reader.clone(), writer: self.writer.clone() }
    }
}

/// Validate a line against the max length of an assuan message.
/// 
/// Silently truncate the line if it exeeds the maximum length.
fn validate_line(mut line: Vec<u8>) -> Vec<u8> {
    let mut end = line.iter().position(|b| *b == b'\n').unwrap_or(line.len());
    end = end.min(LINE_LENGHT - 1);
    line.resize(end, 0);
    line
}

/// Encode the given string with percent-encoding.
/// 
/// Encode spaces (' '), new lines ('\n'), carriage return ('\r'), plus ('+') and percent ('%')
pub fn encode_percent(str: &str) -> Vec<u8> {
    str.as_bytes().iter().flat_map(|&b| {
        if b == b'%' || b == b' ' || b == b'+' || b == b'\n' || b == b'\r' {
            return format!("%{:02X}", b).as_bytes().to_vec();
        }
        vec![b]
    }).collect()
}

/// Decode a percent-encoded buffer.
/// 
/// If the encoding is not valid return the raw bytes.
pub fn decode_percent(data: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let mut decoded = Vec::new();
    while i < data.len() {
        if data[i] == b'%' {
            if let Ok(d) = hex::decode(&data[i+1..i+3]) {
                decoded.extend(d);
                i += 3;
            } else {
                decoded.push(data[i]);
                i += 1;
            }
        } else {
            decoded.push(data[i]);
            i += 1;
        }
    }
    decoded
}

/// Return the path of the socket file, as provided by `gpgconf`.
/// 
/// # Errors
/// Return an [`std::io::Error`] if the call of `gpgconf` failed.
/// 
/// # Panic
/// Panic if the path is not UTF8-encoded.
fn get_socket_file_path() -> Result<PathBuf, std::io::Error> {
    let output = Command::new("gpgconf")
        .args(["--list-dirs", "agent-socket"])
        .output()?;
    let path = PathBuf::from(String::from_utf8(output.stdout).expect("Socket path is not UTF8").trim());
    Ok(path)
}

/// Return the path to the original `gpg-agent`, as provided by `gpgconf`.
/// 
/// # Errors
/// Return an [`std::io::Error`] if the call of `gpgconf` failed.
/// 
/// # Panic
/// Panic if the path is not UTF8-encoded.
fn get_original_agent() -> Result<PathBuf, std::io::Error> {
    let mut gpgconf = PathBuf::from("gpgconf");
    if cfg!(target_os = "windows") {
        gpgconf.set_extension("exe");
    }
    let output = Command::new(&gpgconf)
        .args(["--list-dirs", "bindir"])
        .output()?;

    let mut path = PathBuf::from(String::from_utf8(output.stdout).expect("Agent path is not UTF8").trim());
    path.push("gpg-agent");
    if cfg!(target_os = "windows") {
        path.set_extension("exe");
    }

    Ok(path)
}