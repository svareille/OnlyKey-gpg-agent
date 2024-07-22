use std::{path::{Path, PathBuf}, process::Command};
use anyhow::{Result, Context};

pub fn get_homedir(gpg_bin_path: Option<&Path>) -> Result<PathBuf> {
    let gpgconf_path: PathBuf = match gpg_bin_path {
        Some(path) => {
            let mut path = path.join("gpgconf");
            if cfg!(target_os = "windows") {
                path.set_extension("exe");
            }
            path
        },
        None => PathBuf::from("gpgconf"),
    };

    let output = Command::new(gpgconf_path)
        .args(["--list-dirs", "homedir"])
        .output().context("Call to gpgconf failed")?;
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}