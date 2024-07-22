//! OnlyKey-gpg-agent is automatically started by gpg when needed.
//! The underlying `gpg-agent` is started in server mode, thus only accessible by the running
//! instance of OnlyKey-gpg-agent

use std::{path::PathBuf, thread, sync::{mpsc::{channel, Sender, Receiver}, Arc, Mutex, RwLock}};

use anyhow::{Result, bail, Context};
use clap::Parser;
use log::{info, debug, error, trace, warn};

#[cfg(not(windows))]
use daemonize::Daemonize;
use ok_gpg_agent::{utils, config::Settings};

#[macro_use]
extern crate lazy_static;

use crate::{assuan::{AssuanListener, AssuanCommand, AssuanClient, AssuanServer, AssuanResponse, ClientError}, agent::{handle_client, MyAgent, ServerResponseFilter}};

mod assuan;
mod agent;
mod csexp;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Set the name of the home directory
    /// This argument is passed to the original gpg-agent.
    #[arg(long)]
    homedir: Option<PathBuf>,

    /// Unused, here for compatibility reasons.
    /// This argument is passed to the original gpg-agent.
    #[arg(long, action)]
    use_standard_socket: bool,

    /// Start the agent as a daemon.
    /// This argument is passed to the original gpg-agent.
    #[arg(long, action)]
    daemon: bool,

    /// Load the configuration file (`ok-agent.toml`), check if it's valid and exit.
    #[arg(long, conflicts_with_all=["daemon", "use_standard_socket"])]
    check_conf: bool,
}

fn main() -> Result<()> {
    setup_logger().context("Problem with logger")?;

    if let Err(e) = Args::try_parse() {
        match e.kind() {
            clap::error::ErrorKind::DisplayVersion | clap::error::ErrorKind::DisplayHelp => {},
            _ => error!("Failed to parse command line: {:?}", e),
        }
    }

    let args = Args::parse();

    if args.check_conf {
        let homedir = match args.homedir.as_deref() {
            Some(home) => home.to_owned(),
            None => match utils::get_homedir(None) {
                Ok(home) => home,
                Err(e) => {
                    eprintln!("Could not get the homedir: {e:?}");
                    bail!("check-conf failed");
                }
            },
        };
        let mut config_file = homedir;
        config_file.push("ok-agent.toml");
        println!("Checking configuration from {}...", config_file.display());
        match Settings::new(config_file.as_path()) {
            Ok(settings) => {
                println!("Config file successfully read: \n{:#?}", settings);
            },
            Err(e) => {
                println!("Config file is invalid: {e:?}");
            }
        }
        return Ok(());
    }
    
    info!("Agent started with arguments: {:?}", args);

    let homedir = match args.homedir.as_deref() {
        Some(home) => home.to_owned(),
        None => match utils::get_homedir(None) {
            Ok(home) => home,
            Err(e) => {
                error!("Could not get the homedir: {e:?}");
                bail!(e);
            }
        },
    };

    info!("Working with homedir {}", homedir.display());

    let mut config_file = homedir.clone();

    config_file.push("ok-agent.toml");

    if args.daemon {
        daemonize().context("Could not daemonize the process")?;
    }

    let settings = Settings::new(config_file.as_path()).map_err(|e| {
        error!("Could not load settings: {:?}", e);
        e
    })?;

    info!("Setting log level to {}", settings.log_level);
    set_log_level(settings.log_level);

    let srf: Arc<Mutex<Vec<ServerResponseFilter>>> = Arc::new(Mutex::new(Vec::new()));
    let srf_1 = srf.clone();
    let mut my_agent = MyAgent::new(config_file, settings, srf_1);
    
    let agent_path = if my_agent.settings.agent_program.as_os_str().is_empty() {None} else {Some(my_agent.settings.agent_program.as_path())};
    let gpgconf_path = if my_agent.settings.gpgconf.as_os_str().is_empty() {None} else {Some(my_agent.settings.gpgconf.clone())};

    let mut server = AssuanServer::new(homedir.as_path(), args.use_standard_socket, agent_path)
        .map_err(|e| {
            error!("Could not create assuan server: {:?}", e);
            e
        })?;
    server.connect().map_err(|e| {
        error!("Could not connect to gpg-agent: {:?}", e);
        e
    })?;

    info!("Testing agent's responsiveness");
    server.send(AssuanCommand::Nop).map_err(|e| {
        error!("Could not send NOP to gpg-agent: {:?}", e);
        e
    })?;
    match server.recv() {
        Ok(AssuanResponse::Ok(_)) => {
            info!("Agent correctly responding");
        },
        Ok(res) => {
            error!("Agent behave unexpectedly: expected OK, got {:#?}", res);
            panic!("The agent should have responded with OK, not {:?}", res);
        }
        Err(e) => {
            error!("Could not receive data from gpg-agent: {:?}", e);
            bail!(e);
        }
    };

    my_agent.server = Some(server.clone());

    let my_agent = Arc::new(Mutex::new(my_agent));

    let (sender, receiver) = channel();
    //let receiver = Arc::new(Mutex::new(receiver));
    
    // Receive messages from server
    {
        info!("Handling server...");
        let server = server.clone();
        thread::spawn(move || {
            if let Err(e) = handle_server(server, sender) {
                error!("Server handling got interrupted: {:?}", e);
            }
        });
    }

    let shared_client: Arc<Mutex<Option<AssuanClient>>> = Arc::new(Mutex::new(None));
    // Dispatch message to client, if any
    {
        info!("Handling messages dispatching to client...");
        let client = Arc::clone(&shared_client);
        let server = server.clone();
        thread::spawn(move || {
            if let Err(e) = dispatch_to_client(receiver, client, server, srf) {
                error!("Message dispatching to client got interrupted: {:?}", e);
            }
        });
    }

    info!("Setup listener...");
    let assuan_listener = AssuanListener::new(homedir.as_path(), gpgconf_path.as_deref(), my_agent.lock().unwrap().settings.delete_socket).map_err(|e| {
        error!("Couldn't setup the assuan listener: {:?}", e);
        e
    })?;

    debug!("Waiting for client connection");
    while let Ok(mut client) = assuan_listener.accept() {
        debug!("GPG client attempting connection...");
        if let Err(e) = client.connect() {
            info!("Couldn't connect client: {:?}", e);
            continue;
        }
        info!("Good client");
        *(shared_client.lock().unwrap()) = Some(client.clone());

        // Update settings
        let config_file = my_agent.lock().unwrap().config_file.clone();
        my_agent.lock().unwrap().settings = Settings::new(&config_file).map_err(|e| {
            error!("Could not load settings: {:?}", e);
            e
        })?;
        // Reset log level
        set_log_level(my_agent.lock().unwrap().settings.log_level);

        // Connect to an OnlyKey, silently continue if an error occurs
        if let Err(e) = my_agent.lock().unwrap().try_connect_device() {
            error!("Could not connect to an OnlyKey: {:?}", e);
        }

        let agent = Arc::clone(&my_agent);
        match handle_client(client, server.clone(), agent) {
            Ok(true) => {
                break;
            },
            Ok(false) => {},
            Err(e) => {
                if let Some(ClientError::Eof) =  e.downcast_ref::<ClientError>() {
                    info!("Client disconnected");
                } else {
                    warn!("Client handling stopped: {}", e);
                }
            },
        }
        // Disconnect OnlyKey
        my_agent.lock().unwrap().disconnect_device();

        *(shared_client.lock().unwrap()) = None;
        debug!("Waiting for client connection");
    }

    server.close().map_err(|e| {
        error!("Couldn't close server connection: {:?}", e);
        e
    })?;

    info!("Exiting...");
    Ok(())
}

lazy_static! {
    static ref LOG_LEVEL: RwLock<log::LevelFilter> = RwLock::new(log::LevelFilter::Info);
}

/// Set log level dynamically at runtime
fn set_log_level(level: log::LevelFilter) {
    let loglevel = LOG_LEVEL.read().unwrap();
    if level != *loglevel {
        drop(loglevel);
        let msg = match LOG_LEVEL.write() {
            Ok(mut log) => {
                *log = level;
                Ok(format!("Log level changed to: {}", level))
            }
            Err(err) => {
                Err(format!("Failed to change log level to: {}, cause: {}", level, err))
            }
        };
        match msg {
            Ok(msg) => info!("{}", msg),
            Err(msg) => warn!("{}", msg),
        }
        
    }
}

#[cfg(windows)]
fn setup_logger() -> Result<(), fern::InitError> {
    use std::env;

    let mut logger = fern::Dispatch::new()
        .filter(|metadata| {
            match LOG_LEVEL.read() {
                Ok(log) => metadata.level() <= *log,
                Err(_err) => true,
            }
        })
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}]{} [{}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                record.file().unwrap_or("?"),
                record.line().map(|l| l.to_string()).unwrap_or_default(),
                message
            ))
        })
        //.level(level)
        .chain(std::io::stdout());

    let mut log_file = env::temp_dir();
    log_file.push("ok-gpg-agent.log");
    if let Ok(log_file) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(log_file) {
        logger = logger.chain(log_file);
    } else {
        logger = logger.chain(std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open("ok-gpg-agent.log")?);
    }
    logger.apply()?;
    Ok(())
}

#[cfg(not(windows))]
fn setup_logger() -> Result<(), fern::InitError> {

    let syslog_formatter = syslog::Formatter3164::default();

    let with_format = fern::Dispatch::new()
        //.level(level)
        .filter(|metadata| {
            match LOG_LEVEL.read() {
                Ok(log) => metadata.level() <= *log,
                Err(_err) => true,
            }
        })
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}]{} [{}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                record.file().unwrap_or("?"),
                record.line().map(|l| l.to_string()).unwrap_or_default(),
                message
            ))
        });

    let mut logger = fern::Dispatch::new()
        .chain(
            with_format
                .chain(std::io::stdout())
        );
    if let Ok(syslog) = syslog::unix(syslog_formatter) {
        logger = logger.chain(
            fern::Dispatch::new()
                .filter(|metadata| {
                    match LOG_LEVEL.read() {
                        Ok(log) => metadata.level() <= *log,
                        Err(_err) => true,
                    }
                })
                //.level(level)
                .chain(syslog)
        );
    } else {
        logger = logger.chain(
            fern::Dispatch::new()
                .filter(|metadata| {
                    match LOG_LEVEL.read() {
                        Ok(log) => metadata.level() <= *log,
                        Err(_err) => true,
                    }
                })
                //.level(level)
                .chain(std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/ok-gpg-agent.log")?)
        );
    }
    logger.apply()?;
    Ok(())
}

#[cfg(windows)]
fn daemonize() -> Result<()> {
    info!("No daemonization on Windows, the process is already detached");
    Ok(())
}
 
#[cfg(not(windows))]
fn daemonize() -> Result<()> {
    let daemonize = Daemonize::new()    // is optional, see `Daemonize` documentation
            .working_directory("/tmp");
        
        match daemonize.start() {
            Ok(_) => {
                info!("Successfully daemonized");
                Ok(())
            },
            Err(e) => {
                error!("Could not daemonize: {:?}", e);
                bail!(e)
            },
        }
}

fn handle_server(mut server: AssuanServer, client: Sender<AssuanResponse>) -> Result<()>{
    trace!("[handle_server] Listening to server");
    loop {
        let data = server.recv()?;
        debug!("[handle_server] Got {:?}", data);
        client.send(data)?;
    }
}

fn dispatch_to_client(receiver: Receiver<AssuanResponse>, client: Arc<Mutex<Option<AssuanClient>>>, mut server: AssuanServer, srf: Arc<Mutex<Vec<ServerResponseFilter>>>) -> Result<()> {
    while let Ok(data) = receiver.recv() {
        if let Some(client) = client.lock().unwrap().as_mut() {
            let mut srf = srf.lock().unwrap();
            match srf.last() {
                Some(ServerResponseFilter::CancelInquire) => {
                    match data {
                        AssuanResponse::Inquire{ .. } => {
                            debug!("Got Inquire from server, canceling it");
                            srf.pop();
                            server.send(AssuanCommand::Cancel)?;
                            continue;
                        },
                        _ => {client.send(data)?;}
                    }
                },
                Some(ServerResponseFilter::OkOrErr) => {
                    match data {
                        AssuanResponse::Ok(_) | AssuanResponse::Err { .. } => {
                            debug!("Got Ok or Err from server, ignoring it");
                            srf.pop();
                            continue;
                        },
                        _ => {client.send(data)?;}
                    }
                },
                Some(ServerResponseFilter::Processing) => {
                    match data {
                        AssuanResponse::Processing { .. } => {
                            debug!("Got Processing from server, ignoring");
                            srf.pop();
                            continue;
                        },
                        _ => {client.send(data)?;}
                    }
                },
                Some(ServerResponseFilter::Inquire) => {
                    match data {
                        AssuanResponse::Inquire{ .. } => {
                            debug!("Got Inquire from server, ignoring");
                            srf.pop();
                            continue;
                        },
                        _ => {client.send(data)?;}
                    }
                },
                None => {client.send(data)?;},
            }
        } else {
            warn!("No client attached, yet message {:?} received from server", data);
        }
    }
    Ok(())
}