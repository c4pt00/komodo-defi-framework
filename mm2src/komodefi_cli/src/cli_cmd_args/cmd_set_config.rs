use crate::error_anyhow;
use anyhow::{anyhow, Result};
use clap::Args;
use common::log::error;
use inquire::{Confirm, Text};
use std::fs::File;
use std::io::Read;

const DEFAULT_RPC_URL: &str = "127.0.0.1:7789";

#[derive(Args)]
#[group(required = false, multiple = true)]
pub(crate) struct SetConfigArgs {
    #[arg(long, short, help = "Set if you are going to set up a password")]
    pub(crate) password: Option<bool>,
    #[arg(long, short, visible_alias = "url", help = "KomoDeFi RPC API Uri. localhost:7789")]
    pub(crate) uri: Option<String>,
    #[arg(
        long,
        short,
        help = "Set `Yes` if you want to use secure connection with your mm2 rpc. RPC should supported secure!"
    )]
    pub(crate) secure_conn: Option<bool>,
    #[arg(long, short, help = "Set configuration from path")]
    pub(crate) from_path: Option<String>,
}

impl SetConfigArgs {
    pub(crate) fn inquire(&mut self) -> Result<()> {
        self.inquire_secure_connection()?;
        self.inquire_uri()?;
        self.inquire_password()
    }

    fn inquire_password(&mut self) -> Result<()> {
        if self.password.is_none() {
            self.password = Confirm::new("Set if you are going to set up a password:")
                .with_default(false)
                .with_placeholder("No")
                .prompt()
                .map_err(|error| error_anyhow!("Failed to get password option: {error}"))?
                .into();
        }

        Ok(())
    }

    fn inquire_secure_connection(&mut self) -> Result<()> {
        if self.secure_conn.is_none() {
            self.secure_conn = Confirm::new("Use secure connection for rpc uri:")
                .with_default(false)
                .with_placeholder("No")
                .prompt()
                .map_err(|error| error_anyhow!("Failed to get secure_conn option: {error}"))?
                .into();
        }

        Ok(())
    }

    fn inquire_uri(&mut self) -> Result<()> {
        if self.uri.is_none() {
            self.uri = Text::new("What is the rpc_uri without https/http?:")
                .with_placeholder(DEFAULT_RPC_URL)
                .with_default(DEFAULT_RPC_URL)
                .prompt()
                .map_err(|error| error_anyhow!("Failed to get rpc_uri: {error}"))?
                .into();
        }
        Ok(())
    }

    pub fn source_from_path(&self, path: &str) -> Result<(String, String)> {
        let mut file = File::open(path).map_err(|error| error_anyhow!("Failed to get rpc_uri: {error}"))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|error| error_anyhow!("Failed to get rpc_uri: {error}"))?;

        let mm2: Mm2Config = serde_json::from_str(&String::from_utf8_lossy(&buffer))
            .map_err(|error| error_anyhow!("Failed to get rpc_uri: {error}"))?;

        let base = if mm2.secure_conn.unwrap_or_default() {
            "https://"
        } else {
            "http://"
        };
        Ok((
            format!(
                "{base}{}:{}",
                mm2.rpcip.to_string().trim(),
                mm2.rpcport.to_string().trim()
            ),
            mm2.rpc_password.to_string().trim().to_string(),
        ))
    }
}

#[derive(serde::Deserialize)]
struct Mm2Config {
    rpcip: String,
    rpcport: u16,
    secure_conn: Option<bool>,
    rpc_password: String,
}
