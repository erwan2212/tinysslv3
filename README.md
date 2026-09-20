# tinySSL

A lightweight OpenSSL 3.0 command-line tool written in Free Pascal for Windows.

> Built on top of [MWA Software OpenSSL Pascal bindings](https://github.com/MWASoftware/IndyTLS-OpenSSL).

---

## Requirements

- Windows (x64)
- `libcrypto-3-x64.dll` and `libssl-3-x64.dll` in the same directory
- Optionally `ossl-legacy.dll` for legacy algorithms (MD5, RC4, DES, Blowfish...)

---

## Global parameters

These parameters can be combined with any command:

| Parameter | Description |
|---|---|
| `--password=<pwd>` | Password or passphrase. Can also be provided via **stdin** (recommended to avoid exposure in process list) |
| `--algo=<name>` | Algorithm name. Use `--list_cipher` or `--list_digest` to see available names |
| `--key=<path>` | Path to a private key file, or raw key bytes for encrypt/decrypt |
| `--cert=<path>` | Path to a X.509 certificate file |
| `--csr=<path>` | Path to a Certificate Signing Request file |
| `--in=<path>` | Path to input file |
| `--out=<path>` | Path to output file |
| `--cn=<name>` | Common Name (CN) for certificate generation |
| `--alt=<value>` | Subject Alternative Name, e.g. `DNS:*.example.com` or `IP:1.2.3.4` |
| `--ca=true` | Flag: mark certificate as a CA (self-signed root) |
| `--ca=<path>` | Path to CA certificate file (for signing or verification) |
| `--iv=<hex>` | IV (Initialization Vector) in hex, used by encrypt/decrypt |
| `--utf16` | Treat input as UTF-16 encoded (default: false) |
| `--debug=true` | Enable verbose debug output |

> **Security note:** Avoid passing `--password` directly on the command line as it appears in process lists and shell history. Use stdin instead:
> ```
> echo mypassword| tinySSL --signreq --csr=req.csr --ca=ca.crt
> ```

---

## Certificate commands

### `--mkcert` — Generate a self-signed certificate

Creates a self-signed certificate and its private key.

```
tinySSL --mkcert [--out=<file>] [--cn=<name>] [--algo=<algo>] [--ca=true] [--key=<existing_key>] [--password=<pwd>]
```

| Parameter | Default | Description |
|---|---|---|
| `--out` | `ca.crt` | Output certificate file (`.key` is created alongside) |
| `--cn` | `_Root Authority_` | Common Name |
| `--algo` | `RSA` | Key algorithm: `RSA`, `EC`, `EC384`, `EC521`, `ED25519` |
| `--ca` | false | Mark as CA certificate (adds `basicConstraints: critical,CA:TRUE`) |
| `--key` | *(generated)* | Reuse an existing private key |
| `--password` | | Password to protect the generated private key |

**Examples:**
```
tinySSL --mkcert --out=ca.crt --cn="My Root CA" --ca=true --algo=RSA
tinySSL --mkcert --out=server.crt --cn="myserver.local" --algo=EC384
tinySSL --mkcert --out=ca.crt --cn="My CA" --ca=true --algo=ED25519
```

---

### `--mkreq` — Generate a Certificate Signing Request (CSR)

```
tinySSL --mkreq [--out=<file>] [--cn=<name>] [--key=<existing_key>]
```

| Parameter | Default | Description |
|---|---|---|
| `--out` | `request.csr` | Output CSR file (`.key` created alongside if no `--key`) |
| `--cn` | `localhost` | Common Name |
| `--key` | *(generated)* | Reuse an existing private key |

**Examples:**
```
tinySSL --mkreq --out=server.csr --cn="www.example.com"
tinySSL --mkreq --out=server.csr --cn="myapp" --key=server.key
```

---

### `--signreq` — Sign a CSR with a CA certificate

```
tinySSL --signreq [--csr=<file>] [--cert=<ca_cert>]  [--ca=true] [--password=<pwd>] [--alt=<san>]
```

| Parameter | Default | Description |
|---|---|---|
| `--csr` | `request.csr` | Input CSR file |
| `--cert` | `ca.crt` | CA certificate used for signing (`.key` loaded automatically) |
| `--ca` | false | Mark as CA certificate (adds `basicConstraints: critical,CA:TRUE`) |
| `--password` | | CA private key password |
| `--alt` | | Subject Alternative Name(s) |

Output: `<csr_name>.crt`

**Examples:**
```
tinySSL --signreq --csr=request.csr --cert=ca.crt --password=password
tinySSL --signreq --csr=request.csr --cert=ca.crt --alt="DNS:*.example.com,IP:192.168.1.1"
```

---

### `--verify` — Verify a certificate against a CA

```
tinySSL --verify --cert=<cert> --ca=<ca_cert>
```

**Examples:**
```
tinySSL --verify --cert=request.crt --ca=ca.crt
```

---

### `--set_password` — Change or remove private key password

```
tinySSL --set_password --key=<keyfile> [--password=<new_pwd>]
```

Omit `--password` to remove the password (write key in clear).

**Examples:**
```
tinySSL --set_password --key=server.key --password=newpassword
tinySSL --set_password --key=server.key
```

---

## Inspect commands

### `--print_cert` — Display certificate details

```
tinySSL --print_cert --cert=<file>
```

Displays: subject, issuer, public key (PEM + hex + SHA-1), modulus, key usage, validity dates, fingerprints (SHA-1 + SHA-256).

---

### `--print_private` — Display private key details

```
tinySSL --print_private --key=<file> [--password=<pwd>]
```

---

### `--print_request` — Display CSR details

```
tinySSL --print_request --cert=<file>
```

---

### `--print_sshkey` — Display public key in OpenSSH format

```
tinySSL --print_sshkey --key=<file>
```

Supports RSA and ECDSA keys (P-256, P-384, P-521).

**Example output:**
```
ssh-rsa AAAAB3NzaC1yc2EAAAA...
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...
```

---

## Format conversion

### `--p12topem` — Convert PFX/P12 to PEM

```
tinySSL --p12topem --in=cert.pfx [--password=<pwd>]
```

Output: `cert.crt` + `cert.key`

---

### `--pemtop12` — Convert PEM to PFX/P12

```
tinySSL --pemtop12 --in=cert.crt [--key=<keyfile>] [--password=<pwd>]
```

Output: `cert.pfx`

---

### `--p7topem` — Convert P7B to PEM

```
tinySSL --p7topem --in=cert.p7b
```

Output: `cert.crt`

---

### `--pemtop7` — Convert PEM to P7B

```
tinySSL --pemtop7 --in=cert.crt
```

Output: `cert.p7b`

---

### `--dertopem` — Convert DER (binary) to PEM (Base64)

```
tinySSL --dertopem --in=cert.der
tinySSL --dertopem --key=private.der
```

---

### `--pemtoder` — Convert PEM to DER (binary)

```
tinySSL --pemtoder --in=cert.crt
tinySSL --pemtoder --key=private.key
```

---

## Cryptography commands

### `--encrypt` / `--decrypt` — Symmetric encryption

```
tinySSL --encrypt --algo=<cipher> --password=<data> [--key=<hex>] [--iv=<hex>]
tinySSL --decrypt --algo=<cipher> --password=<hex> [--key=<hex>] [--iv=<hex>]
```

If `--key` or `--iv` are omitted, random values are generated and displayed.  
Input for `--decrypt` must be in hexadecimal.

**Examples:**
```
tinySSL --encrypt --algo=AES-256-CBC --password=hello
tinySSL --decrypt --algo=AES-256-CBC --password=<hex> --key=<hex> --iv=<hex>
```

---

### `--encrypt_pub` / `--decrypt_priv` — Asymmetric RSA encryption

```
tinySSL --encrypt_pub --in=<file>
tinySSL --decrypt_priv --in=<file>
```

Uses `public.pem` / `private.pem` in the current directory.

---

### `--hash` — Hash data

```
tinySSL --hash --algo=<digest> --password=<data>
```

**Examples:**
```
tinySSL --hash --algo=SHA-256 --password=hello
tinySSL --hash --algo=SHA3-256 --password=hello
echo hello | tinySSL --hash --algo=SHA-256
```

---

### `--base64encode` / `--base64decode`

```
tinySSL --base64encode --password=<data>
tinySSL --base64decode --password=<base64> [--utf16]
```

---

### `--tohexa` / `--fromhexa`

```
tinySSL --tohexa --password=hello
tinySSL --fromhexa --password=68656C6C6F
```

---

## Utility commands

### `--genkey` — Generate RSA 2048-bit key pair

```
tinySSL --genkey
```

Output: `public.pem` + `private.pem` in current directory.

---

### `--rand` — Generate cryptographically secure random hex

```
tinySSL --rand
```

---

### `--dhparam` — Generate DH parameters

```
tinySSL --dhparam --out=<file>
```

---

### `--list_cipher` / `--list_digest`

```
tinySSL --list_cipher
tinySSL --list_digest
```

Lists all algorithms available from the loaded OpenSSL providers.

---

## Typical workflow: CA → Server certificate

```bash
# 1. Generate a root CA
tinySSL --mkcert --out=ca.crt --cn="My Root CA" --ca=true --algo=RSA

# 2. Generate a CSR for the server
tinySSL --mkreq --out=server.csr --cn="www.example.com"

# 3. Sign the CSR with the CA
tinySSL --signreq --csr=server.csr --cert=ca.crt --alt="DNS:www.example.com,DNS:*.example.com"

# 4. Verify the result
tinySSL --verify --cert=server.crt --ca=ca.crt

# 5. Inspect the certificate
tinySSL --print_cert --cert=server.crt
```

---

## Typical workflow: create ssh key

```bash
Exemple to generate a public/private key pair and convert into into a open ssh key for ssh purpose:
tinySSL.exe --genkey
tinyssl.exe --print_sshkey --filename=public.pem
rem now copy your ssh pub key to your ssh server authorized_keys
rem lets secure the local windows private key
icacls private.pem /inheritance:r
icacls private.pem /grant:r "%USERNAME%:F"
ssh -i private.pem username@ip

## ini configuration file (`tinyssl.ini`)

Certificate fields and extensions are read from `tinyssl.ini` in the current directory:

```ini
[cert]
C=FR
O=My Organisation

[cert_ext]
key_usage=critical,keyCertSign,cRLSign
; subject_key_identifier=hash
; ext_key_usage=critical,serverAuth,clientAuth

[req]
C=FR
O=My Organisation

[req_ext]
key_usage=critical,nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
subject_key_identifier=hash
ext_key_usage=critical,OID:1.3.6.1.5.5.7.3.2,OID:1.3.6.1.5.5.7.3.1
```

---

## Source

[https://github.com/erwan2212](https://github.com/erwan2212)
