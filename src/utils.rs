use std::{path::PathBuf, process::Command};
use anyhow::Result;

pub fn get_homedir() -> Result<PathBuf> {
    let output = Command::new("gpgconf")
        .args(["--list-dirs", "homedir"])
        .output()?;
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}