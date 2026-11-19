# sshkeystore — Learning Notes

This file records how `sshkeystore` was built, how to run it, how it was
verified, and the important details discovered along the way.

## Goal

Build a small Rust daemon that:

- registers a virtual FIDO2 HID device through Linux UHID;
- speaks CTAPHID/CTAP2 to `libfido2` / OpenSSH;
- supports `ssh-keygen -t ed25519-sk`;
- supports resident keys (`-O resident`) and downloading them with
  `ssh-keygen -K`;
- asks for confirmation through `pinentry`;
- stores the generated key in SQLite;
- logs every key creation to the terminal.

The reference projects were `../bouncer` and `../fidorium`. Only the minimum
needed pieces were reimplemented here.

## Project layout

```text
sshkeystore/
├── Cargo.toml
├── Cargo.lock
└── src/
    ├── main.rs                 # CLI parsing, logging, runtime startup
    ├── config.rs               # database path and pinentry options
    ├── keys.rs                 # Ed25519 key generation/signing, COSE encoding
    ├── store.rs                # SQLite credential storage
    ├── up.rs                   # pinentry confirmation + CTAPHID KEEPALIVE
    ├── hid/
    │   ├── mod.rs
    │   ├── device.rs           # /dev/uhid registration
    │   ├── report.rs           # FIDO HID report descriptor
    │   └── transport.rs        # UHID read/write threads
    ├── ctaphid/
    │   ├── mod.rs              # CTAPHID loop, dispatch, INIT, PING, CANCEL
    │   ├── channel.rs          # CID allocation and message reassembly
    │   ├── packet.rs           # 64-byte packet parsing/encoding
    │   └── types.rs            # CTAPHID commands and constants
    └── ctap2/
        ├── mod.rs              # CTAP2 command dispatch, shared CtapState
        ├── types.rs            # MakeCredential/GetAssertion request parsing
        ├── get_info.rs         # authenticatorGetInfo
        ├── make_credential.rs  # key creation and SQLite insert
        ├── get_assertion.rs    # credential lookup and signing
        ├── client_pin.rs       # clientPIN (PIN protocol 1, P-256 ECDH, AES-CBC)
        ├── cred_management.rs  # resident credential enumeration (0x0A)
        ├── authenticator_data.rs
        └── attestation.rs      # packed self-attestation
```

## Creation process

1. **Started from the working reference implementations.**
   `fidorium` already had a functioning UHID transport, CTAPHID framing,
   channel handling, KEEPALIVE logic, and pinentry integration. Those parts
   were copied/adapted. `bouncer` supplied the SQLite credential-store pattern.

2. **Replaced TPM ownership of private keys with SQLite.**
   `fidorium` stores TPM-wrapped keys. Here the private key is just a 32-byte
   Ed25519 seed stored in SQLite. The database file is created with mode
   `0600`.

3. **Added Ed25519 instead of P-256.**
   OpenSSH requests COSE algorithm `-8` (EdDSA) for
   `ssh-keygen -t ed25519-sk`. The daemon therefore uses `ed25519-dalek` and
   returns an OKP COSE key:

   ```text
   { 1: 1,      # kty = OKP
     3: -8,     # alg = EdDSA
    -1: 6,      # crv = Ed25519
    -2: <32-byte public key> }
   ```

   `-19` is also accepted as an alias during enrollment because some
   authenticators advertise it, but OpenSSH currently requests `-8`.

4. **Implemented only the CTAP2 commands OpenSSH needs.**
   - `authenticatorGetInfo` (`0x04`)
   - `authenticatorMakeCredential` (`0x01`)
   - `authenticatorGetAssertion` (`0x02`)
   - `authenticatorClientPIN` (`0x06`, PIN protocol 1)
   - `authenticatorCredentialManagement` (`0x0A`)

   CTAPHID `INIT`, `PING`, `WINK`, `CANCEL`, and `KEEPALIVE` are also handled.

   Resident keys required advertising `credProtect`, `credMgmt`, `clientPin`,
   and `pinProtocols` in GetInfo, then implementing the clientPIN key
   agreement / PIN token exchange and credential management enumeration.

5. **Used pinentry as the user-presence gate.**
   A confirmation dialog is shown for both enrollment and signing. While the
   dialog is open, `KEEPALIVE` packets are sent every 100 ms so libfido2 and
   Firefox/OpenSSH do not abort the operation.

6. **Used packed self-attestation.**
   During enrollment the daemon signs `authData || clientDataHash` with the new
   Ed25519 credential key. `libfido2` calls `fido_cred_verify_self()` when the
   attestation format is `packed`, so this signature must be correct.

## How to run

Build:

```bash
cd /home/user/playground/pkitowebauthn/sshkeystore
cargo build --release
```

Run the daemon in a terminal:

```bash
./target/release/sshkeystore
```

Then, from another terminal:

```bash
ssh-keygen -t ed25519-sk -f ~/.ssh/bouncer_key
```

Expected behaviour:

1. `ssh-keygen` discovers the virtual FIDO2 device.
2. `pinentry` opens with a "Confirm" dialog.
3. Confirming creates the key.
4. The daemon prints a line such as:

   ```text
   KEY CREATED (stored in SQLite) rp_id=ssh: account=openssh credential_id=... alg=-8 discoverable=false
   ```

5. `~/.ssh/bouncer_key` and `~/.ssh/bouncer_key.pub` are written by OpenSSH.

Signing also works:

```bash
ssh-keygen -Y sign -f ~/.ssh/bouncer_key -n file ~/some/file
```

Resident keys:

```bash
ssh-keygen -t ed25519-sk -O resident -O user=alice \
  -f ~/.ssh/bouncer_resident -N ''
```

Download resident keys (prompts for the FIDO2 PIN; any PIN is accepted by
this implementation):

```bash
SSH_ASKPASS=/path/to/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  ssh-keygen -K
```

`ssh-keygen -K` writes `id_ed25519_sk_rk_<user>` and `.pub` in the current
directory. The downloaded key can then sign normally.

### Multiple resident keys

OpenSSH derives the download filename from the resident key's `user_id`:

```text
id_ed25519_sk_rk_<user_id>
```

The `user_id` comes from `-O user=...` at enrollment (maximum 31 characters).
Without `-O user`, OpenSSH uses a 32-byte all-zero user ID. `sk_suffix()`
trims the trailing zeros, so every such key maps to the same filename
`id_ed25519_sk_rk`; `ssh-keygen -K` then asks to overwrite and the last key
wins.

To download several resident keys without overwriting, give each key a
distinct user:

```bash
ssh-keygen -t ed25519-sk -O resident -O user=alpha -f ~/key-alpha -N ''
ssh-keygen -t ed25519-sk -O resident -O user=beta  -f ~/key-beta  -N ''
ssh-keygen -K
# Saved ED25519-SK key ssh: to id_ed25519_sk_rk_alpha
# Saved ED25519-SK key ssh: to id_ed25519_sk_rk_beta
```

Keys already stored with an all-zero user ID keep colliding; re-enroll them
with `-O user=...` to give them distinct names.

## Options

```bash
sshkeystore --help
```

Useful flags:

- `--db PATH` — override the SQLite database path.
- `--pinentry BIN` — choose a pinentry binary
  (e.g. `pinentry-curses`, `pinentry-gnome3`, or a test script).
- `-v` / `-vv` — more logging (`debug` / `trace`).

Default database path on Linux:

```text
~/.local/share/sshkeystore/sshkeystore.sqlite
```

The database and its WAL files are created on first start. The database file
is set to mode `0600`.

## SQLite schema

```sql
CREATE TABLE credentials (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id         TEXT NOT NULL,
    rp_id_hash    BLOB NOT NULL,
    user_id       BLOB NOT NULL,
    user_name     TEXT,
    user_display  TEXT,
    alg           INTEGER NOT NULL,
    private_key   BLOB NOT NULL,
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    discoverable  INTEGER NOT NULL DEFAULT 0,
    cred_prot     INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
```

`cred_prot` stores the credential-protection level requested during
enrollment (OpenSSH asks for `2`, user-verification optional with credential
ID). Older databases get the column through an `ALTER TABLE` migration.

`private_key` is the raw 32-byte Ed25519 seed. `public_key` is the 32-byte
Ed25519 public key. `rp_id` is `ssh:` for OpenSSH; `user_name` and
`user_display` are both `openssh` by default.

Inspect it with:

```bash
sqlite3 ~/.local/share/sshkeystore/sshkeystore.sqlite \
  'select rp_id, user_name, alg, sign_count, discoverable, cred_prot,
          hex(credential_id) from credentials;'
```

## Permissions

The daemon needs read/write access to `/dev/uhid`. On this machine:

```text
crw-rw---- root plugdev /dev/uhid
```

The user must be in the `plugdev` group. If not, either add the user to the
group or install a udev rule granting access. The created `/dev/hidrawN`
device is what `libfido2` and OpenSSH actually use.

## End-to-end verification performed

A fake pinentry was used to auto-confirm prompts during automated testing:

```bash
cat > /tmp/fake-pinentry <<'PY'
#!/usr/bin/env python3
import sys
print("OK Pleased to meet you", flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    cmd = line.split(" ", 1)[0].upper()
    if cmd == "BYE":
        print("OK", flush=True)
        break
    print("OK", flush=True)
PY
chmod +x /tmp/fake-pinentry
```

The initial `OK Pleased to meet you` greeting is required; without it the
`pinentry` crate waits forever for the server greeting.

Daemon:

```bash
./target/debug/sshkeystore \
  --db /tmp/sshkeystore-final/keys.sqlite \
  --pinentry /tmp/fake-pinentry
```

Device detection:

```bash
fido2-token -L
# /dev/hidraw0: vendor=0x1209, product=0x5353 ( sshkeystore FIDO2)
```

Enrollment and signing:

```bash
ssh-keygen -t ed25519-sk -f /tmp/sshkeystore-final/bouncer_key -N ''
printf 'sign me\n' > /tmp/sshkeystore-final/msg
ssh-keygen -Y sign -f /tmp/sshkeystore-final/bouncer_key \
  -n test /tmp/sshkeystore-final/msg
```

Both completed successfully, and SQLite contained:

```text
('ssh:', 'openssh', -8, 1, '610BB855...C662A')
```

The signature counter incremented after `GetAssertion`.

Resident-key round trip with three keys:

```bash
for user in alpha beta gamma; do
  ssh-keygen -t ed25519-sk -O resident -O user=$user \
    -f /tmp/enroll/$user -N ''
done
cd /tmp/download
SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 ssh-keygen -K
```

with `/tmp/askpass` simply printing the PIN. `ssh-keygen -K` reported:

```text
Saved ED25519-SK key ssh: to id_ed25519_sk_rk_alpha
Saved ED25519-SK key ssh: to id_ed25519_sk_rk_beta
Saved ED25519-SK key ssh: to id_ed25519_sk_rk_gamma
```

All three downloaded public-key fingerprints matched their enrolled keys.
Signing with each downloaded key and verifying with `ssh-keygen -Y verify`
also succeeded.

When the same test is run without `-O user`, all three keys have an all-zero
user ID and `ssh-keygen -K` repeatedly targets `id_ed25519_sk_rk`, prompting
to overwrite. This is OpenSSH filename selection, not credential enumeration:
the daemon returned all three keys.

## Problems encountered and fixes

### 1. `libfido2` rejected `GetInfo` as “invalid cbor”

The first version advertised the CTAP 2.1 `algorithms` field (key `10`) even
though the device only claimed `FIDO_2_0`. The installed `libfido2` did not
accept that combination:

```text
ctap_check_cbor: invalid cbor
decode_algorithm: ...
fido_dev_open_rx: falling back to u2f
```

Fix: removed key `10` from the `GetInfo` response. A CTAP 2.0 device only
needs keys 1–5.

### 2. `GetAssertion` failed with “invalid format”

The assertion response’s credential descriptor was encoded as:

```cbor
{"type": "public-key", "id": ...}
```

CTAP2 requires canonical CBOR, where shorter text keys come first. The correct
order is:

```cbor
{"id": ..., "type": "public-key"}
```

`libfido2`'s `cbor_decode_cred_id()` enforced this ordering. After swapping
the keys, `ssh-keygen -Y sign` worked.

### 3. UHID report-ID byte

Linux hidraw may prepend a `0x00` report-ID byte. The transport strips it only
when the report is 65 bytes long and starts with zero.

### 4. Reader/writer deadlock avoidance

The UHID reader runs in one thread and a separate writer thread sends
responses. A single blocking reader that also writes can deadlock while the
host waits for a reply.

### 5. KEEPALIVE during pinentry

Hosts abort FIDO operations that appear silent. KEEPALIVE packets are sent
every 100 ms while pinentry is open and while the response is being prepared.

### 6. `ssh-keygen -K` failed before sending clientPIN

`GetInfo` advertised `clientPin: true` but omitted `pinProtocols` (key `6`).
`libfido2`'s `fido_dev_get_pin_protocol()` returned `0`, so
`cbor_encode_pin_opt()` returned `NULL`, `fido_dev_authkey_tx()` failed, and
`credman_tx()` aborted with `FIDO_ERR_INTERNAL` — surfaced by OpenSSH as
`invalid format`. The daemon saw no `0x06`/`0x0A` traffic at all.

Fix: advertise `pinProtocols: [1]` (CTAP PIN protocol 1) in GetInfo.

### 7. Credential-management `rkBegin` rejected as missing parameter

The request carries `rpIdHash` as a nested map:

```cbor
{1: 4, 2: {1: <32-byte hash>}, 3: 1, 4: <pinUvAuthParam>}
```

The first implementation looked for raw bytes at key `2`, returned
`MissingParameter` (`0x14`), and `libfido2` reported `invalid format`.
Handle both a raw byte string and the nested `{1: hash}` map.

### 8. Resident credential ID must be a descriptor map

In an `rk` credential-management entry, key `7` is a
`PublicKeyCredentialDescriptor`, not a raw byte string:

```cbor
{"id": <credential id>, "type": "public-key"}
```

`libfido2` calls `cbor_decode_cred_id()` on it and requires canonical key
order (`id` before `type`). Encoding raw bytes caused `cbor type` followed by
`invalid format`.

### 9. Repeated key-agreement/PIN-token traffic during `-K`

OpenSSH performs several credential-management operations (`getCredsMetadata`,
`rpBegin`, `rkBegin`). `libfido2` obtains a fresh ECDH key agreement and PIN
token for each one, so the daemon sees repeated `0x06` exchange pairs. This is
normal.

## Current limitations / notes

- Only Ed25519 (`ed25519-sk`, COSE `-8`) is supported. `ecdsa-sk` (P-256)
  is not implemented.
- Private keys are stored unencrypted in SQLite. The database is mode `0600`,
  but anyone who can read the file can use the keys. This was chosen for a
  basic implementation.
- Client PIN is implemented only enough for OpenSSH's resident-key download.
  PIN protocol 1 is supported; the supplied PIN hash is decrypted but not
  verified, and there is no `setPIN`/`changePIN`. Any PIN supplied by the
  askpass helper is accepted.
- Credential management implements metadata, RP enumeration, and resident
  credential enumeration (`rkBegin`/`rkNext`). Deleting or updating resident
  credentials and `rpNext` pagination beyond the in-memory snapshot are not
  implemented.
- `credProtect` is recorded and returned, but not enforced. User verification
  (`uv`) is advertised as unsupported; user presence is still the pinentry
  dialog.
- The resident-credential limit reported in metadata is hard-coded to 100.
- Resident keys created without `-O user=` all use OpenSSH's default all-zero
  user ID. They enumerate correctly, but `ssh-keygen -K` maps them to the
  same `id_ed25519_sk_rk` filename and overwrites earlier downloads. Enroll
  with distinct `-O user=` values when storing multiple resident keys.
- User presence is a simple pinentry Yes/Cancel dialog, not a touch sensor.
- Linux only, as requested.
- The daemon expects to run in a user session with access to `/dev/uhid` and
  a usable pinentry (the terminal/curses variant works well).
