# RCON

A synchronous [Source RCON] library for Rust. This is a personal learning
project; primarily tested for Minecraft.

## Usage

The crate can be used a library in other Rust applications, or as a CLI.

### Library

```rust
use std::error::Error;
use rcon::Connection;

fn main() -> Result<(), Box<dyn Error>> {
    let mut conn = Connection::connect("localhost:25575", "password")?;
    let response = conn.exec("list")?;
    println!("{response}");
    Ok(())
}
```

### CLI

The `cli` feature flag installs a binary `rcon`, which can dispatch one-off
commands or start an interactive RCON terminal.

```sh
cargo install -F cli --git https://github.com/lsjoeberg/rcon
```

#### Usage

```txt
Usage: rcon [OPTIONS] -p <PASSWORD> [-- <COMMANDS>...]

Arguments:
  [COMMANDS]...

Options:
  -H <HOST>          Server address [env: RCON_HOST=] [default: localhost]
  -P <PORT>          Server port [env: RCON_PORT=] [default: 25575]
  -p <PASSWORD>      RCON password [env: RCON_PASS=]
  -t                 Terminal mode
  -h, --help         Print help
```

<!--References-->
[Source RCON]: https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
