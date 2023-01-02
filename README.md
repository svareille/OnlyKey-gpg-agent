# OnlyKey GPG agent

This ok-gpg-agent is a proxy between a gpg client and the original gpg-agent.
It checks wether an OnlyKey is plugged and use it for signing/decryption if relevent.

My typical use case is when I sign commits. I want my private key on my computer and on my OnlyKey
for convenience, so that when I sign a commit I just have to touch my OnlyKey if plugged or entering my
passphrase as usual if not. **Note:** the private keys does not need to be present
on both the OnlyKey and the computer. You can have your private keys solely on your OnlyKey, or
solely on your computer.

This agent **does not** replace the original gpg-agent. It works as a proxy between a client
(usually gpg) and gpg-agent.

Works with:
- `gpg`
- GpgOL
- Kleopatra
- Mailvelope
- ...

## Usage

Just use `gpg` or any gpg client as usual and if your OnlyKey is plugged and correctly configured
signing and decryption will be done by your key (if the corresponding private key is loaded in your
OnlyKey of course).

If the `challenge` option of `ok-agent.toml` is `"true"` or not given you will be invited to enter
a 3-digits chalenge on your OnlyKey on signing and decryption. If your OnlyKey is configured to ask
for a challenge on PGP and SSH operations ("Stored Key User Input Mode" in the OnlyKey App) you will
have to enter the previously shown code on the OnlyKey, otherwise simply touch a button to allow
the operation.

## Differences with [`onlykey-agent`](https://docs.onlykey.io/onlykey-agent.html)

OnlyKey can be used for both SSH and PGP (https://docs.onlykey.io/onlykey-agent.html) using the
official python package `onlykey-agent`. So, what are the differencies with this project?

First of all, the official `onlykey-agent` package supports SSH with the convenient command
`onlykey-agent identity@myhost -c`. Onlykey GPG Agent does not. So let's compare with `onlykey-gpg`,
the official GPG agent for OnlyKey.

| Official `onlykey-gpg` | OnlyKey GPG Agent |
| -- | -- |
| Works on Linux and Mac (Windows soon?). | Works on Windows, Linux and Mac (not tested). |
| Separate standard computer-hosted keys and onlykey-hosted keys, so that both cannot be used at the same time. | Interract with the original gpg-agent so that both computer-hosted and onlykey-hosted keys can be used at the same time. |
| Need to unset `GNUPGHOME` to use computer-hosted keys. | Don't need to do anything to switch between computer-hosted and onlykey-hosted keys. |

I initially began this project in order to have a way to use my PGP keys from my OnlyKey on Windows,
while having a seamless experience (not having to use special commands or having to choose between
configurations with keys on computer and keys on device). Theses two requirements are not satisfied
by the official onlykey-agent, thus #fineilldoitmyself. Plus it was a great opportunity to code
something in Rust.

## Known bugs/limitations

- Signing with an RSA key of 4096 bits may not work. See https://github.com/trustcrypto/libraries/issues/25 for more details.
- ~~Derived keys are not supported yet.~~ Derivated keys are now supported!

## Install

### Windows and standard systems

First, get the path of the `gpg.conf` file:
```shell
$ gpgconf -L homedir
```
Then, in this file, add the line
```
agent-program path/to/ok-gpg-agent.exe
```

If gpg-agent is already running either restart the computer, kill the process or use the command
```shell
$ gpg-connect-agent KILLAGENT /bye
```

### Debian with systemd

On some Linux (Debian and derivatives) the gpg-agent is automatically started by systemd.
The service file is `gpg-agent.service`, located in `/usr/lib/systemd/user/`.

To use `ok-gpg-agent` with systemd, copy the binary in `/usr/bin/`
```shell
sudo cp ok-gpg-agent /usr/bin/
```
then make a backup of `/usr/lib/systemd/user/gpg-agent.service` and replace the line `ExecStart=/usr/bin/gpg-agent --supervised -v`
by `ExecStart=/usr/bin/ok-gpg-agent` in the original service file.

```shell
sudo cp /usr/lib/systemd/user/gpg-agent.service /usr/lib/systemd/user/gpg-agent.service.bak
sudo nano /usr/lib/systemd/user/gpg-agent.service
```

Restart the service (`sudo systemctl restart gpg-agent`) or kill the agent (`gpg-connect-agent KILLAGENT /bye`).

## Configure

### Agent

Create the file `ok-agent.toml` in the homedir of gpg. This file will contain the configuration of
the agent.

For *ok-gpg-agent* to know which private key is in which slot, you must add the keygrip of the key
in a `[[keyinfo]]` section as follow :

```toml
[[keyinfo]]
slot = "ECC1"
keygrip = "BBD680E5AD45D0FEDD2E90A34F1CEC9A6744D096"
```

The `slot` field can be any of `RSA1` .. `RSA4`, `ECC1` .. `ECC16`.

For RSA slots, a field `size` containing the size of the key in bits must be present:

```toml
[[keyinfo]]
slot = "RSA1"
keygrip = "5B3E86D2F867BA1135F3754CAE4F82409F8D0AE6"
size = 4096
```

For derivated key the `slot` field must not be present. Instead `identity` and `ecc_type` are required:

```toml
[[keyinfo]]
identity = "My identity (comment) <my.dentity@example.com>"
ecc_type = "Ed25519"
keygrip = "7787EDEE866D4A3534BF5B5B9E20A3F7D616AF50"
```

`ecc_type` can be any of `Ed25519` (signature key), `Cv25519` (decryption key), `Nist256P1` and
`Secp256K1`.

To obtain the keygrip of a key, run:
```shell
$ gpg --with-keygrip -k
```

Each private key must have its own `[[keyinfo]]` section.

#### Options of `ok-agent.toml`

The possible global options of `ok-agent.toml` are:

- `challenge`: boolean indicating if a challenge must be entered to authorize signature and
  decryption. Default to `"true"`.
- `log_level`: the log level. Must be one of (case-incensitive) `"off"`, `"error"`, `"warn"`,
  `"info"`, `"debug"` or `"trace"`. Default to `"info"`.
- `agent_program`: path to the original *gpg-agent*. If `""`, the agent advertized by `gpg-conf`
  will be used. Default to `""`.
- `delete_socket`: boolean indicating if the Unix socket must be deleted if already present. Only
  used on Unix. Default to `"false"`.

Theses options are optional.

Example config file:
```toml
challenge = "false"
log_level = "error"

[[keyinfo]]
slot = "ECC1"
keygrip = "BBD680E5AD45D0FEDD2E90A34F1CEC9A6744D096"

[[keyinfo]]
slot = "ECC2"
keygrip = "F897F717026CAB4E3CE8E5055F527B260D012824"

```

### Derivated key creation

To generate (or re-generate) a derivated key, use the `ok-gen-key` command-line tool.

This will construct a public key pair from the given identity. The generation is roughly the same as
the official onlykey-gpg: the same identity string will generate the same public key, with the
exception of accentuated or non-ASCII identity. For exemple, the official onlykey-gpg will produce
the same public key for `"aeiou"` and `"àéïòù"` whereas `ok-gen-key` will produce two different
keys.

Key generation can be done interactively or using command-line options.

```console
Usage: ok-gen-key.exe [OPTIONS]

Options:
      --identity <IDENTITY>
          Identity from which to generate the new key.

          "My Name <my.name@example.com>", "My Name" and "asdf" are all valid identity producing different keys. If given, the key will be generated without asking for any parameter. These must be given as command line arguments.

  -c, --curve <KEY_KIND>
          Kind of key to generate. Defaults to ed25519

          [possible values: ed25519, nist256, secp256]

      --validity <VALIDITY>
          How long the key should be valid. Defaults to 2 years.

                   0 = key does not expire
                <n>  = key expires in n days
                <n>w = key expires in n weeks
                <n>m = key expires in n months
                <n>y = key expires in n years

  -t, --time <TIME>
          Generate the key with a custom creation date.

          This allows for rebuilding the exact same public key as a previous generation. This date correspond to the UNIX time.

  -o, --output <OUTPUT>
          Path to the file where to write the newly generated key.

          As the produced key is ASCII-armored, it is recommended to end the filename with '.asc'. If not given the generated key is printed to stdout.        

      --homedir <HOMEDIR>
          Set the path of the gpg's home directory.

          This option is used with --export-key, --export-config and --auto.

  -e, --export-key
          Export the generated pubic key in the gpg keyring.

          The export is done with the `gpg` command. If --homedir is given it will be passed to `gpg`.

  -a, --auto
          Automatically export the generated public key in the gpg keyring and append the OnlyKey configuration to the `ok-agent.toml` file.

          This option have the same effect as both --export-key and --export-config. If --homedir is given it will be used as the directory containing the gpg 
keyring and the `ok-agent.toml` file.

  -x, --export-config [<FILE>]
          Append the generated configuration to the `ok-agent.toml` file.

          If a path to a file is given, this file will be written. Otherwise if --homedir is given it will be used as the directory containing the `ok-agent.toml` file.

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```

## Troubleshooting

### `ok-gpg-agent` is not started

If `ok-gpg-agent` is not started even though `gpg.conf` is correctly configured you can check a few
things:

#### `gpg.conf`

Check if `gpg.conf` is correctly loaded. Look at `gpg --debug extprog -K`.

#### `ok-gpg-agent`

Check if `ok-gpg-agent` starts when called directly on the command line.

If the error "Address already in use" is displayed and you are on Linux, remove the Unix
socket file (its path is shown a few lines above).

### OnlyKey not recognized

On Linux, don't forget to follow the [Using OnlyKey with Linux](https://docs.onlykey.io/linux.html)
guide to communicate with OnlyKey.

### Log file

The log file is written in:
- Unix:
  - A syslog if present (`journalctl --user -ef`);
  - The temporary directory otherwise, ofently `/tmp/ok-gpg-agent.log`.
- Windows:
  - The user temporary directory, ofently `C:/Users/<user>/AppData/Local/Temp/ok-gpg-agent.log`.

Be warned that under "debug" or "trace" log level, sensitive information can be outputed. The
default log level is "info", which **should** not print any sensitive data.

The log level can be changed in the `ok-agent.toml` file.

### Paths

OnlyKey-gpg-agent get most of its path from `gpgconf`. If anything strange happened (such as no
agent deployed), check the output of `gpgconf --list-dirs` in the context of the process calling
the agent.
