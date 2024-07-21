use std::{process::{Command, Stdio}, io::Write, path::{PathBuf, Path}, fs::{File, OpenOptions}};

use anyhow::{Result, bail, anyhow, Context};

use chrono::{DateTime, Local, Duration, NaiveDate, TimeZone};
use clap::{Parser, ValueEnum};

use ok_gpg_agent::{config::{KeyInfo, EccType, DerivedKeyInfo}, utils};
use regex::Regex;
use lazy_static::lazy_static;
use serde::Serialize;
use text_io::read;
use thiserror::Error;

mod gen_key;

use crate::gen_key::gen_key;

/// Generate a new PGP key pair from a plugged OnlyKey.
/// 
/// The `gpg` command must be available.
#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// Identity from which to generate the new key.
    /// 
    /// "My Name <my.name@example.com>", "My Name" and "asdf" are all valid identity producing
    /// different keys.
    /// If given, the key will be generated without asking for any parameter. These must be given
    /// as command line arguments.
    #[arg(long)]
    identity: Option<String>,

    /// Kind of key to generate. Defaults to ed25519.
    #[arg(short = 'c', long = "curve", value_enum)]
    key_kind: Option<EccKind>,

    /// How long the key should be valid. Defaults to 2 years.
    /// 
    ///          0 = key does not expire
    ///       <n>  = key expires in n days
    ///       <n>w = key expires in n weeks
    ///       <n>m = key expires in n months
    ///       <n>y = key expires in n years
    #[arg(long, value_parser = parse_validity_duration, verbatim_doc_comment )]
    validity: Option<Duration>,

    /// Generate the key with a custom creation date.
    /// 
    /// This allows for rebuilding the exact same public key as a previous generation.
    /// This date correspond to the UNIX time.
    #[arg(short, long, value_parser = parse_time)]
    time: Option<DateTime<Local>>,

    /// Path to the file where to write the newly generated key.
    /// 
    /// As the produced key is ASCII-armored, it is recommended to end the filename with '.asc'.
    /// If not given the generated key is printed to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Set the path of the gpg's home directory.
    /// 
    /// This option is used with --export-key, --export-config and --auto.
    #[arg(long)]
    homedir: Option<PathBuf>,

    /// Export the generated pubic key in the gpg keyring.
    /// 
    /// The export is done with the `gpg` command. If --homedir is given it will be passed to `gpg`.
    #[arg(short, long)]
    export_key: bool,
    
    /// Automatically export the generated public key in the gpg keyring and append the
    /// OnlyKey configuration to the `ok-agent.toml` file.
    /// 
    /// This option have the same effect as both --export-key and --export-config.
    /// If --homedir is given it will be used as the directory containing the gpg keyring and the
    /// `ok-agent.toml` file.
    #[arg(short, long)]
    auto: bool,

    /// Append the generated configuration to the `ok-agent.toml` file.
    /// 
    /// If a path to a file is given, this file will be written. Otherwise if --homedir is given it
    /// will be used as the directory containing the `ok-agent.toml` file.
    #[arg(short='x', long, name="FILE")]
    export_config: Option<Option<PathBuf>>,

    /// Export the parameters used to generate the key in the configuration file.
    /// 
    /// Save the validity and creation date in `ok-agent.toml` so that the key can be rebuilt again
    /// if the public part is lost.
    /// This parameter is only relevant with --export-config and --auto.
    #[arg(short='p', long)]
    export_parameters: bool,
}

fn main() -> Result<()> {
    let mut args = Args::parse();

    if args.time.is_none() {
        args.time = Some(Local::now());
    }

    if args.identity.is_none() {
        // Interactive mode

        while args.key_kind.is_none() {
            println!("Please select the kind of key you want:
    (1) Curve 25519
    (2) NIST P-256
    (3) secp256
Your selection? ");
            match read!() {
                1 => args.key_kind = Some(EccKind::Ed25519),
                2 => args.key_kind = Some(EccKind::Nist256),
                3 => args.key_kind = Some(EccKind::Secp256),
                _ => println!("Invalid selection."),
            }
        }
        while args.validity.is_none() {
            println!("Please specify how long the key should be valid.
       0 = key does not expire
    <n>  = key expires in n days
    <n>w = key expires in n weeks
    <n>m = key expires in n months
    <n>y = key expires in n years
Key is valid for? ");
            let validity: String = read!();
            match parse_validity_duration(&validity) {
                Ok(val) => {
                    if val.is_zero() {
                        println!("Key does not expire at all.");
                    } else {
                        println!("Key expires at {}.", expire_at(val, args.time.unwrap()).context("Could not compute expiration time")?);
                    }
                    println!("Is this correct? (y/N)");
                    if let 'y' = read!() {
                        args.validity = Some(val)
                    }
                },
                Err(e) => println!("Invalid selection: {}", e),
            }
        }

        println!(r#"Please now enter the identity of this key.
The identity string will be formed as "Real name (Comment) <Email>""#);
        let mut name: Option<String> = None;
        let mut email: Option<String> = None;
        let mut comment: Option<String> = None;

        'identity : loop {
            if name.is_none() {
                print!("Real name: ");
                let line: String = read_line!();
                name = Some(line.trim().to_owned());
            }

            if email.is_none() {
                print!("Email address: ");
                let line: String = read_line!();
                email = Some(line.trim().to_owned());
                while !email.as_ref().unwrap().is_empty() && !validate_email(email.as_ref().unwrap()) {
                    print!("Email address: ");
                    let line: String = read_line!();
                    email = Some(line.trim().to_owned());
                }
            }

            if comment.is_none() {
                print!("Comment: ");
                let line: String = read_line!();
                comment = Some(line.trim().to_owned());
            }

            let identity = {
                let name = name.as_ref().unwrap();
                let email = email.as_ref().unwrap();
                let comment = comment.as_ref().unwrap();
                if name.is_empty() {
                    if comment.is_empty() {
                        email.to_owned()
                    } else {
                        format!("({}){}", comment, if email.is_empty() {String::new()} else {format!(" <{}>", email)})
                    }
                } else if comment.is_empty() {
                    if email.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{} <{}>", name, email)
                    }
                } else if email.is_empty() {
                    format!("{} ({})", name, comment)
                } else {
                    format!("{} ({}) <{}>", name, comment, email)
                }
            };

            println!("You selected this USER-ID:");
            println!("    \"{}\"", identity);
            args.identity = Some(identity);
            loop {
                println!("Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?");
                match read!() {
                    'O' | 'o' => break 'identity,
                    'Q' | 'q' => {
                        println!("Key generation aborted.");
                        return Ok(());
                    },
                    'N' | 'n' => {
                        name = None;
                        break;
                    },
                    'C' | 'c' => {
                        comment = None;
                        break;
                    },
                    'E' | 'e' => {
                        email = None;
                        break;
                    },
                    _ => {},
                }
            }
        }
    }

    // Default values

    if args.key_kind.is_none() {
        args.key_kind = Some(EccKind::Ed25519);
    }

    if args.validity.is_none() {
        args.validity = Some(parse_validity_duration("2y").unwrap());
    }

    // Now, every parameters are in `args`.

    let identity = args.identity.unwrap();
    let key_kind = args.key_kind.unwrap();
    let validity = args.validity.unwrap();
    let creation = args.time.unwrap();

    println!("About to generate a {:?} key, valid until {} for the identity \"{}\"", key_kind, expire_at(validity, creation).context("Could not compute expiration time")? , identity);
    println!("To regenerate the same key, use the same parameters and add \"--time {}\"", creation.timestamp());
    println!();
    println!("You will be asked twice to authorize two signing operation.
If you have enabled 'challenge mode' for derived key, you will have to enter two 3-digit challenges.
Make sure your OnlyKey is plugged in and unlocked.
Press Enter when you are ready to continue.");

    std::io::stdin().read_line(&mut String::new()).unwrap();

    let armored_key = gen_key(identity.clone(), key_kind, creation.into(), validity).context("Could not generate the key")?;

    if args.export_key || args.auto {
        gpg_export_key(&armored_key, &args.homedir).context("Could not export the generated key into the keyring")?;
    }

    let keygrips = keygrips_from_gpg(&armored_key).context("Could not get the keygrip of the generated key")?;

    let sign_key_info = KeyInfo::DerivedKey(DerivedKeyInfo{
        identity: identity.clone(),
        ecc_type: match key_kind {
            EccKind::Ed25519 => EccType::Ed25519,
            EccKind::Nist256 => EccType::Nist256P1,
            EccKind::Secp256 => EccType::Secp256K1,
        },
        keygrip: keygrips[0].clone(),
        validity: validity.num_days(),
        creation: creation.timestamp(),
    });
    let decrypt_key_info = KeyInfo::DerivedKey(DerivedKeyInfo{
        identity,
        ecc_type: match key_kind {
            EccKind::Ed25519 => EccType::Cv25519,
            EccKind::Nist256 => EccType::Nist256P1,
            EccKind::Secp256 => EccType::Secp256K1,
        },
        keygrip: keygrips[1].clone(),
        validity: validity.num_days(),
        creation: creation.timestamp(),
    });
 
    let dummy_settings = DummySettings {keyinfo: vec![sign_key_info, decrypt_key_info]};

    match args.output {
        Some(filename) => {
            let mut file = File::create(&filename).with_context(||format!("Unable to open file {}", filename.display()))?;
            file.write_all(armored_key.as_bytes()).with_context(|| format!("Unable to write key to file {}", filename.display()))?;
        },
        None => {
            println!("Your public key:\n{}", armored_key);
            println!();
        },
    }
    
    if args.export_config.is_some() || args.auto {
        let config_file = match args.export_config {
            Some(Some(filename)) => filename,
            Some(None) | None => {
                let mut config_file = match args.homedir.as_deref() {
                    Some(home) => home.to_owned(),
                    None => utils::get_homedir().context("Could not get the homedir")?,
                };
            
                config_file.push("ok-agent.toml");
                config_file
            },
        };
        append_config_to_file(&dummy_settings, &config_file).with_context(|| format!("Could not append the configuration to the config file {}", config_file.display()))?;
        println!("Configuration written to {}", config_file.display());
    } else {
        println!("Please add the following lines to your 'ok-agent.toml':");
        println!("{}", toml::to_string(&dummy_settings).context("Could not serialize the configuration to TOML")?);
    }
    Ok(())
}

#[derive(Serialize)]
struct DummySettings {
    keyinfo: Vec<KeyInfo>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[derive(Debug)]
enum EccKind{
    Ed25519,
    Nist256,
    Secp256,
}

#[derive(Error, Debug)]
pub enum ValidityError {
    #[error("Wrong format for validity of the key: {0}")]
    WrongFormat(String),
}

fn parse_validity_duration(arg: &str) -> Result<Duration> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^(?P<num>\d*)(?P<unit>[wmy])?$").unwrap();
    }
    match RE.captures(arg) {
        Some(caps) => {
            let num: i64 = caps.name("num").ok_or_else(|| ValidityError::WrongFormat(arg.to_string()))?.as_str().parse()?;
            match caps.name("unit") {
                None => {
                    Ok(Duration::days(num))
                },
                Some(unit) => match unit.as_str() {
                    "w" => Ok(Duration::weeks(num)),
                    "m" => {
                        Ok(Duration::days(num*30))
                    },
                    "y" => {
                        Ok(Duration::days(num*365))
                    },
                    _ => bail!(ValidityError::WrongFormat(arg.to_string()))
                },
                
            }
        },
        None => bail!(ValidityError::WrongFormat(arg.to_string()))
    }
}

fn parse_time(arg: &str) -> Result<DateTime<Local>> {
    match Local.timestamp_opt(arg.parse::<i64>()?, 0) {
        chrono::LocalResult::None =>Err(anyhow!("The provided time is not valid")),
        chrono::LocalResult::Single(time) => Ok(time),
        chrono::LocalResult::Ambiguous(_, _) => unreachable!(),
    }
}

fn expire_at(validity: Duration, creation: DateTime<Local>) -> Result<DateTime<Local>> {
    creation.checked_add_signed(validity).ok_or_else(|| anyhow!("Validity too big"))
}

pub fn get_days_from_month(year: i32, month: u32) -> i64 {
    NaiveDate::from_ymd_opt(
        match month {
            12 => year + 1,
            _ => year,
        },
        match month {
            12 => 1,
            _ => month + 1,
        },
        1,
    ).unwrap()
    .signed_duration_since(NaiveDate::from_ymd_opt(year, month, 1).unwrap())
    .num_days()
}

/// Verify that an email address is correct.
/// We only verify if the string contains an @ as it is roughly the only required character.
fn validate_email(input: &str) -> bool {
    input.contains('@')
}

/*fn keygrip() -> String {
    let keygrip = Sha1::new()
        .chain_update(data)
        .finalize();
    
    hex::encode_upper(keygrip)
}*/

/// Return keygrip of provided key by parsing `gpg` output.
/// 
/// Needs `gpg` to be installed and accessible.
fn keygrips_from_gpg(armored_key: &str) -> Result<Vec<String>> {
    let mut gpg = Command::new("gpg")
        .args(["--show-keys", "--with-keygrip", "--with-colons"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn().context("Could not invoke `gpg`")?;
    
    gpg.stdin
        .as_mut()
        .ok_or_else(||anyhow!("Child process stdin has not been captured!"))?
        .write_all(armored_key.as_bytes()).context("Could not send the armored key to gpg")?;
    
    let output = gpg.wait_with_output().context("Could not grab gpg's output")?;
    if output.status.success() {
        let raw_output = String::from_utf8(output.stdout).context("Could not convert gpg's output to UTF-8")?;
        let mut keygrips = Vec::new();
        for line in raw_output.lines() {
            lazy_static! {
                static ref RE: Regex = Regex::new(r"^grp:::::::::([[:xdigit:]]{40}):").unwrap();
            }
            if let Some(cap) = RE.captures(line) {
                keygrips.push(cap[1].to_owned());
            }
        }
        if keygrips.is_empty() {
            bail!("No keygrip found in output:\n{}", raw_output);
        }
        Ok(keygrips)
    } else {
        let err = String::from_utf8(output.stderr)?;
        bail!("External command failed:\n {}", err)
    }
}

/// Export the provided key in the gpg's keyring.
/// 
/// This operation is an "import" from the point of view of gpg
/// Needs `gpg` to be installed and accessible.
fn gpg_export_key(key: &str, homedir: &Option<PathBuf>) -> Result<()> {
    let mut gpg = Command::new("gpg");
    gpg.args(["--import",])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(homedir) = homedir {
        gpg.arg("--homedir").arg(homedir.as_os_str().to_str().expect("Cannot convert homedir path to os path"));
    }
    let mut gpg = gpg.spawn().context("Could not invoke `gpg`")?;
    gpg.stdin
        .as_mut()
        .ok_or_else(||anyhow!("Child process stdin has not been captured!"))?
        .write_all(key.as_bytes()).context("Could not send the armored key to gpg")?;
    let output = gpg.wait().context("Could not grab gpg's output")?;

    if output.success() {
        Ok(())
    } else {
        Err(anyhow!("Failed to import key into the gpg keyring"))
    }
}

/// Append the given settings to the provided TOML file.
fn append_config_to_file(dummy_settings: &DummySettings, filename: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename).with_context(|| format!("Could not open file {}", filename.display()))?;
    file.write_all(b"\n\n").with_context(|| format!("Could not write to file {}", filename.display()))?;
    file.write_all(toml::to_string(&dummy_settings).context("Could not serialize the configuration to TOML")?.as_bytes()).with_context(|| format!("Unable to write settings to file {}", filename.display()))
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

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use crate::parse_validity_duration;

    #[test]
    fn validity_good() {
        assert_eq!(parse_validity_duration("0").unwrap(), Duration::zero());
        assert_eq!(parse_validity_duration("10").unwrap(), Duration::days(10));
        assert_eq!(parse_validity_duration("5w").unwrap(), Duration::weeks(5));
        assert_eq!(parse_validity_duration("12m").unwrap(), Duration::days(12*30));
        assert_eq!(parse_validity_duration("2y").unwrap(), Duration::days(2*365));
    }
}