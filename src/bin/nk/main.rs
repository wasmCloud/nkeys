extern crate serde_json;

use clap::{Parser, Subcommand};
use nkeys::{self, KeyPair, KeyPairType};
use serde_json::json;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[command(name = "nk", about = "A tool for manipulating nkeys")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Generates a key pair
    Gen {
        /// The type of key pair to generate. May be Account, User, Module, Service, Server, Operator, Cluster, Curve (xkey)
        keytype: KeyPairType,
        #[arg(
            short = 'o',
            long = "output",
            default_value = "text",
            help = "Specify output format (text or json)"
        )]
        output: Output,
    },
}

#[derive(Debug, Clone)]
enum Output {
    Text,
    Json,
}

impl FromStr for Output {
    type Err = OutputParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Output::Json),
            "text" => Ok(Output::Text),
            _ => Err(OutputParseErr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutputParseErr;

impl Error for OutputParseErr {}

impl fmt::Display for OutputParseErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "error parsing output type, see help for the list of accepted outputs"
        )
    }
}

fn main() {
    let args = Cli::parse();
    let cmd = &args.cmd;
    env_logger::init();

    match cmd {
        Command::Gen { keytype, output } => {
            generate(keytype, output);
        }
    }
}

fn generate(kt: &KeyPairType, output_type: &Output) {
    let kp = KeyPair::new(kt.clone());
    match output_type {
        Output::Text => {
            println!(
                "Public Key: {}\nSeed: {}\n\nRemember that the seed is private, treat it as a secret.",
                kp.public_key(),
                kp.seed().unwrap()
            );
        }
        Output::Json => {
            let output = json!({
                "public_key": kp.public_key(),
                "seed": kp.seed().unwrap(),
            });

            println!("{}", output);
        }
    }
}
