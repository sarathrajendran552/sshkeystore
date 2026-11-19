# sshkeystore

A small Linux daemon that presents a virtual FIDO2 security key over UHID and
stores the resulting SSH credentials in SQLite. It is intended for testing and
development with `libfido2` and OpenSSH's FIDO support.

The virtual authenticator supports:

- `ssh-keygen -t ed25519-sk` enrollment
- Ed25519-SK signing with `ssh-keygen -Y sign`
- Resident keys created with `ssh-keygen -O resident`
- Resident-key download with `ssh-keygen -K`
- User-presence confirmation through `pinentry`
- SQLite-backed credential storage

## Requirements

- Linux with access to `/dev/uhid`
- A Rust toolchain
- OpenSSH built with FIDO/U2F support
- `libfido2` tools for discovery (`fido2-token`)
- A `pinentry` binary

The user running the daemon must have read/write access to `/dev/uhid`.
Depending on the distribution this may require membership in a group such as
`plugdev`, or a custom udev rule.

## Build

```bash
cargo build --release
```

The binary is written to `target/release/sshkeystore`.

## Run

Start the daemon in its own terminal:

```bash
./target/release/sshkeystore
```

The daemon registers a virtual FIDO2 HID device and waits for requests. Use
another terminal for `ssh-keygen` commands.

Check that the device is visible:

```bash
fido2-token -L
```

Example output:

```text
/dev/hidraw0: vendor=0x1209, product=0x5353 ( sshkeystore FIDO2)
```

### Command-line options

```text
Usage: sshkeystore [OPTIONS]

Options:
  -v, --verbose...     Increase log verbosity (-v debug, -vv trace)
      --db <DB>        Override the default SQLite database path
      --pinentry <BIN> pinentry binary used to confirm user presence [default: pinentry]
  -h, --help           Print help
```

Examples:

```bash
./target/release/sshkeystore --db /tmp/sshkeystore.sqlite
./target/release/sshkeystore --pinentry pinentry-curses -v
```

## Quick start

With the daemon running:

```bash
ssh-keygen -t ed25519-sk -f ~/.ssh/sshkeystore_key -N ''
```

Confirm the pinentry dialog. OpenSSH writes the private key and public key.
The daemon logs a line such as:

```text
KEY CREATED (stored in SQLite) rp_id=ssh: account=openssh credential_id=... alg=-8 discoverable=false cred_prot=0
```

Sign a file:

```bash
printf 'hello from sshkeystore\n' > message.txt

ssh-keygen -Y sign -f ~/.ssh/sshkeystore_key -n file message.txt
```

Verify the signature:

```bash
printf 'test %s\n' "$(cat ~/.ssh/sshkeystore_key.pub)" > allowed_signers

ssh-keygen -Y verify -f allowed_signers -I test -n file \
  -s message.txt.sig < message.txt
```

Expected result:

```text
Good "file" signature for test with ED25519-SK key SHA256:...
```

## Resident keys

Create a resident key with a distinct user label:

```bash
ssh-keygen -t ed25519-sk -O resident -O user=alpha \
  -f ~/.ssh/alpha_rk -N ''
```

Download resident keys into the current directory:

```bash
mkdir -p ~/sk-download
cd ~/sk-download
ssh-keygen -K
```

`ssh-keygen -K` asks for the authenticator PIN. This implementation does not
validate the PIN; any non-empty PIN works (for example, `123456`). It then asks
for a passphrase for the downloaded private keys; press Enter twice for no
passphrase.

With `-O user=alpha`, OpenSSH saves:

```text
id_ed25519_sk_rk_alpha
id_ed25519_sk_rk_alpha.pub
```

Downloaded resident keys can sign normally:

```bash
ssh-keygen -Y sign -f id_ed25519_sk_rk_alpha -n file message.txt
```

### Multiple resident keys

OpenSSH derives the download filename from the resident key's user ID. Always
use a distinct `-O user=` for each resident key (up to 31 characters):

```bash
ssh-keygen -t ed25519-sk -O resident -O user=alpha -f ~/alpha -N ''
ssh-keygen -t ed25519-sk -O resident -O user=beta  -f ~/beta  -N ''
ssh-keygen -t ed25519-sk -O resident -O user=gamma -f ~/gamma -N ''
ssh-keygen -K
```

Without `-O user=`, OpenSSH uses an all-zero user ID. Every such key maps to the
same filename `id_ed25519_sk_rk`, so `ssh-keygen -K` will prompt to overwrite
earlier downloads. Re-enroll those keys with distinct `-O user=` values.

## Data storage

Default database path on Linux:

```text
~/.local/share/sshkeystore/sshkeystore.sqlite
```

Override it with `--db PATH`. SQLite WAL mode is used, so the database may have
`-wal` and `-shm` sidecar files. The database file is created with mode `0600`.

The `credentials` table stores the credential ID, relying party, user fields,
algorithm, Ed25519 private/public key material, signature counter, resident-key
flag, credential-protection level, and creation time.

Inspect stored credentials:

```bash
sqlite3 ~/.local/share/sshkeystore/sshkeystore.sqlite \
  'select rp_id, user_name, alg, sign_count, discoverable, cred_prot,
          hex(credential_id) from credentials;'
```

## Security and limitations

This project is a development and testing tool, not a hardware security key.

- Private keys are stored unencrypted in SQLite. The database is mode `0600`,
  but anyone who can read the file can use the keys.
- Only Ed25519/EdDSA (`ed25519-sk`) is supported. `ecdsa-sk` is not implemented.
- The client PIN exchange is implemented for resident-key download, but the PIN
  is not validated. Any PIN is accepted.
- User presence is a pinentry confirmation dialog, not a physical touch sensor.
  An auto-approving pinentry gives no real user-presence protection.
- `credProtect` is recorded and reported but not enforced. User verification
  (`uv`) is not supported.
- Resident credentials are stored in SQLite; the metadata response reports a
  limit of 100 resident credentials.
- Linux only.

## Troubleshooting

**`Key enrollment failed: device not found`**

- Verify the daemon is running.
- Run `fido2-token -L` and confirm the virtual device appears.
- Check read/write access to `/dev/uhid`.

**`pinentry` fails to start**

- Install a pinentry package, or pass an explicit binary:

  ```bash
  ./target/release/sshkeystore --pinentry pinentry-curses
  ```

**`ssh-keygen -K` keeps asking to overwrite**

- The resident keys were enrolled without distinct `-O user=` values. Re-enroll
  them with unique users.

**Multiple FIDO devices are present**

Select the virtual device explicitly using the path reported by
`fido2-token -L`:

```bash
ssh-keygen -t ed25519-sk -O device=/dev/hidraw1 ...
ssh-keygen -K -O device=/dev/hidraw1
```

## Development notes

See [Learning.md](Learning.md) for implementation notes, protocol details,
canonical-CBOR fixes, and the end-to-end verification history.

## License

Licensed under either of MIT or Apache-2.0, at your option.
