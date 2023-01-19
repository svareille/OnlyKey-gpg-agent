use std::{path::PathBuf, process::Command};
use anyhow::{Result, Context};

pub fn get_homedir() -> Result<PathBuf> {
    let output = Command::new("gpgconf1")
        .args(["--list-dirs", "homedir"])
        .output().context("Call to gpgconf failed")?;
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}