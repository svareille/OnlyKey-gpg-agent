use anyhow::{Result, bail, anyhow};

use chrono::{DateTime, Local, Duration, NaiveDate};
use clap::{Parser, ValueEnum};

use regex::Regex;
use lazy_static::lazy_static;
use text_io::read;
use thiserror::Error;

mod onlykey_pgp;
mod gen_key;

use crate::gen_key::gen_key;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /*/// Set the name of the home directory.
    /// If not given, the homedir will be automatically chosen with `gpgconf`.
    #[clap(long)]
    homedir: Option<PathBuf>,*/

    /// Identity from which to generate the new key.
    /// "My Name <my.name@example.com>", "My Name" and "asdf" are all valid identity producing
    /// different keys.
    /// If given, the key will be generated without asking for any parameter. These must be given
    /// as command line arguments.
    #[arg(long)]
    identity: Option<String>,

    /// Kind of key to generate. Defaults to cv25519.
    #[arg(short = 't', long = "type", value_enum)]
    key_kind: Option<EccKind>,

    /// How long the key should be valid. Defaults to 2 years.
    ///          0 = key does not expire
    ///       <n>  = key expires in n days
    ///       <n>w = key expires in n weeks
    ///       <n>m = key expires in n months
    ///       <n>y = key expires in n years
    #[arg(long, value_parser = parse_validity_duration)]
    validity: Option<Duration>,
}

fn main() {
    let mut args = Args::parse();

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
                        println!("Key expires at {}.", expire_at(val).unwrap());
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
                    email = Some(read_line!());
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
                        return;
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

    println!("About to generate a {:?} key, valid until {} for the identity \"{}\"", key_kind, validity, identity);
    println!("Make sure your OnlyKey is plugged in and unlocked.
Press Enter when you are ready to continue.");

    std::io::stdin().read_line(&mut String::new()).unwrap();

    let armored_key = gen_key(identity, key_kind, validity).unwrap();

    println!("Public key:\n{}", armored_key);

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

fn expire_at(validity: Duration) -> Result<DateTime<Local>> {
    let now = Local::now();
    now.checked_add_signed(validity).ok_or_else(|| anyhow!("Validity too big"))
}

pub fn get_days_from_month(year: i32, month: u32) -> i64 {
    NaiveDate::from_ymd(
        match month {
            12 => year + 1,
            _ => year,
        },
        match month {
            12 => 1,
            _ => month + 1,
        },
        1,
    )
    .signed_duration_since(NaiveDate::from_ymd(year, month, 1))
    .num_days()
}

/// Verify that an email address is correct.
/// We only verify if the string contains an @ as it is roughly the only required character.
fn validate_email(input: &str) -> bool {
    input.contains('@')
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

    use crate::{parse_validity_duration};

    #[test]
    fn validity_good() {
        assert_eq!(parse_validity_duration("0").unwrap(), Duration::zero());
        assert_eq!(parse_validity_duration("10").unwrap(), Duration::days(10));
        assert_eq!(parse_validity_duration("5w").unwrap(), Duration::weeks(5));
        assert_eq!(parse_validity_duration("12m").unwrap(), Duration::days(12*30));
        assert_eq!(parse_validity_duration("2y").unwrap(), Duration::days(2*365));
    }
}