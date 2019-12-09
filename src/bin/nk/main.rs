use nkeys::{self, KeyPair, KeyPairType};
use structopt::StructOpt;
use structopt::clap::AppSettings;

#[derive(Debug, StructOpt, Clone)]
#[structopt(
    global_settings(&[AppSettings::ColoredHelp, AppSettings::VersionlessSubcommands]),
    name = "nk",
    about = "A tool for manipulating nkeys"
)]
struct Cli {
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt, Debug, Clone)]
enum Command {
    #[structopt(name = "gen", about = "Generates a key pair")]
    Gen {
        /// The type of key pair to generate. May be Account, User, Module, Server, Operator, Cluster         
        #[structopt(case_insensitive = true)]
        keytype: KeyPairType,
    },
}

fn main() {
    let args = Cli::from_args();
    let cmd = &args.cmd;
    env_logger::init();

    match cmd {
        Command::Gen { keytype } => {
            generate(keytype);
        }
    }
}

fn generate(kt: &KeyPairType) {
    let kp = KeyPair::new(kt.clone());
    println!(
        "Public Key: {}\nSeed: {}\n\nRemember that the seed is private, treat it as a secret.",
        kp.public_key(),
        kp.seed().unwrap()
    );
}
