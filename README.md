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
| Works with derivated keys. | Does not work with derivated keys yet. |

I initially began this project in order to have a way to use my PGP keys from my OnlyKey on Windows,
while having a seamless experience (not having to use special commands or having to choose between
configurations with keys on computer and keys on device). Theses two requirements are not satisfied
by the official onlykey-agent, thus #fineilldoitmyself. Plus it was a great opportunity to code
something in Rust.

## Known bugs/limitations

- Signing with an RSA key of 4096 bits does not work. See https://github.com/trustcrypto/libraries/issues/25 for more details.
- Derived keys are not supported yet.
- Following links in socket file on Unix is not yet supported.
- Under some unknown conditions on Unix, gpg seems to start the agent's process synchronously,
resulting in a deadlock. The only way, for now, to circumvent this problem is to launch
`ok-gpg-agent` manually. Keep in mind that the Unix socket can still be present, preventing any new
instance to start successfully.

## Install

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

## Configure

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

To obtain the keygrip of a key, run:
```shell
$ gpg --with-keygrip -k
```

Each private key must have its own `[[keyinfo]]` section.

### Options of `ok-agent.toml`

The possible global options of `ok-agent.toml` are:

- `challenge`: boolean indicating if a challenge must be entered to authorize signature and
  decryption. Default to `"true"`.
- `log_level`: the log level. Must be one of (case-incensitive) `"off"`, `"error"`, `"warn"`,
  `"info"`, `"debug"` or `"trace"`. Default to `"info"`.
- `agent_program`: path to the original *gpg-agent*. If `""`, the agent advertized by `gpg-conf`
  will be used. Default to `""`.

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

## Troubleshooting

### `ok-gpg-agent` is not started

If `ok-gpg-agent` is not started even though `gpg.conf` is correctly configured you can check a few
things:

- First, check if `gpg.conf` is correctly loaded. Look at `gpg --debug extprog -K`.
- Secondly, check if `ok-gpg-agent` starts when called directly on the command line.

  If the error "Address already in use" is displayed and you are on Linux, remove the Unix
  socket file (its path is shown a few lines above).

### The OnlyKey is not recognized

On Linux, don't forget to follow the [Using OnlyKey with Linux](https://docs.onlykey.io/linux.html)
guide to communicate with OnlyKey.

### Log file

The log file is written in:
- Unix:
  - A syslog if present;
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
