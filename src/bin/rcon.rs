use std::io::{self, stdout, Write};

use clap::Parser;

use rcon::{Connection, RconError};

#[derive(Debug, Parser)]
struct Args {
    /// Server address
    #[arg(short = 'H', default_value = "localhost", env = "RCON_HOST")]
    host: String,
    /// Server port
    #[arg(short = 'P', default_value_t = 25575, env = "RCON_PORT")]
    port: u16,
    /// RCON password
    #[arg(short, env = "RCON_PASS")]
    password: String,
    /// Terminal mode
    #[arg(short)]
    terminal: bool,
    // #[arg(trailing_var_arg = true)]
    #[arg(last = true)]
    commands: Vec<String>,
}

fn main() -> Result<(), RconError> {
    let args = Args::parse();

    let mut conn = Connection::connect(format!("{}:{}", args.host, args.port), &args.password)?;

    if args.terminal {
        run_terminal_mode(conn)?;
    } else {
        let response = conn.exec(&args.commands.join(" "))?;
        println!("{response}");
    }

    Ok(())
}

fn run_terminal_mode(mut conn: Connection) -> Result<(), RconError> {
    println!("Logged in.\nType 'Q' to disconnect.");

    let mut input = String::new();
    loop {
        // Prompt and read user input.
        print!("> ");
        stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        let command = input.trim();

        // No input.
        if command.is_empty() {
            continue;
        }

        // User requested disconnect.
        if command == "Q" {
            break;
        }

        // Execute command.
        let response = conn.exec(command)?;
        println!("{response}");

        input.clear();
    }

    Ok(())
}
