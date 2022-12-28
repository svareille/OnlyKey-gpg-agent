//! OnlyKey-gpg-agent is automatically started by gpg when needed.
//! The underlying `gpg-agent` is started in server mode, thus only accessible by the running
//! instance of OnlyKey-gpg-agent

use std::{path::PathBuf, thread, sync::{mpsc::{channel, Sender}, Arc, Mutex, RwLock}};

use anyhow::{Result, bail};
use clap::{Parser};
use log::{info, debug, error, trace, warn};

#[cfg(not(windows))]
use daemonize::Daemonize;
use ok_gpg_agent::{utils, config::Settings};

#[macro_use]
extern crate lazy_static;

use crate::{assuan::{AssuanListener, AssuanCommand, AssuanClient, AssuanServer, AssuanResponse}, agent::{handle_client, MyAgent, ServerResponseFilter}};

mod assuan;
mod agent;
mod csexp;

fn main() -> Result<()> {

    setup_logger().expect("Problem with logger");

    let args = Args::try_parse().map_err(|e| {
        error!("Failed to parse command line: {:?}", e);
        e
    })?;
    
    info!("Agent started with arguments: {:?}", args);

    if args.daemon {
        daemonize()?;
    }

    info!("Working with homedir {:?}", args.homedir.as_deref());

    let mut config_file = match args.homedir.as_deref() {
        Some(home) => home.to_owned(),
        None => utils::get_homedir().unwrap_or_default(),
    };

    config_file.push("ok-agent.toml");

    let settings = Settings::new(config_file.as_path()).map_err(|e| {
        error!("Could not load settings: {:?}", e);
        e
    })?;

    info!("Setting log level to {}", settings.log_level);
    set_log_level(settings.log_level);

    let srf: Arc<Mutex<Vec<ServerResponseFilter>>> = Arc::new(Mutex::new(Vec::new()));
    let srf_1 = srf.clone();
    let mut my_agent = MyAgent::new(config_file, settings, srf_1).map_err(|e| {
        error!("Could not create MyAgent: {:?}", e);
        e
    })?;
    
    let agent_path = if my_agent.settings.agent_program.as_os_str().is_empty() {None} else {Some(my_agent.settings.agent_program.as_path())};

    let mut server = AssuanServer::new(args.homedir.as_deref(), args.use_standard_socket, agent_path)
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
        thread::spawn(move || -> Result<()> {
            handle_server(server, sender)
        });
    }

    let shared_client: Arc<Mutex<Option<AssuanClient>>> = Arc::new(Mutex::new(None));
    // Dispatch message to client, if any
    {
        info!("Handling messages dispatching to client...");
        let client = Arc::clone(&shared_client);
        let mut server = server.clone();
        thread::spawn(move || -> Result<()> {
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
        });
    }

    info!("Setup listener...");
    let assuan_listener = AssuanListener::new(my_agent.lock().unwrap().settings.delete_socket).map_err(|e| {
        error!("Couldn't setup the assuan listener: {:?}", e);
        e
    })?;

    debug!("Waiting for client connection");
    while let Ok(mut client) = assuan_listener.accept() {
        debug!("GPG attempting connection...");
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

        let my_agent = Arc::clone(&my_agent);
        match handle_client(client, server.clone(), my_agent) {
            Ok(true) => {
                break;
            },
            Ok(false) => {},
            Err(e) => {
                warn!("Client handling stopped: {}", e);
            },
        }
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
   /// Set the name of the home directory
   /// This argument is passed to the original gpg-agent.
   #[clap(long)]
   homedir: Option<PathBuf>,

   /// Unused, here for compatibility reasons.
   /// This argument is passed to the original gpg-agent.
   #[clap(long, action)]
   use_standard_socket: bool,

   /// Start the agent as a daemon.
   /// This argument is passed to the original gpg-agent.
   #[clap(long, action)]
   daemon: bool,
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
