# abe-lsss command-line guide

The CLI provides separate programs for CP/KP setup, key generation, encryption and decryption. Build it with `-DCLI=ON` (the default); the executables are created under `build/cli/`. The `PK` path mentioned in some usage strings is currently marked as under maintenance; use the tools for CP-ABE and KP-ABE only.

Run each command without arguments to print its usage. The tools use short options:

| Program | Purpose | Relevant options |
|---|---|---|
| `abe-setup` | Generate authority parameters | `-s CP|KP`, optional `-p prefix`, optional `-v` |
| `abe-keygen` | Generate a user secret key | `-s CP|KP`, optional `-p prefix`, `-i attributes` for CP or `-i policy` for KP, `-o output`, optional `-v` |
| `abe-encrypt` | Encrypt a file | `-s CP|KP`, optional `-p prefix`, `-e policy` for CP or `-e attributes` for KP, `-i input`, `-o output`, optional `-v` |
| `abe-decrypt` | Decrypt a ciphertext file | `-s CP|KP`, optional `-p prefix`, `-k secret-key-file`, `-i ciphertext`, `-o plaintext`, optional `-v` |
| `abe-policy` | Inspect/evaluate policy input | See its usage output and `cli/POLICY.md`. |

`prefix` is a filename prefix; a dot is added if missing. The default parameter prefix is empty. Setup creates master public/secret files with `.cpabe` or `.kpabe`; the master secret file is sensitive. Key generation adds `.key` to the output name if it is not already present. Encryption appends the scheme suffix to its output filename if absent.

## CP-ABE example

In CP-ABE, the ciphertext carries the policy and the private key carries the user's attributes:

```bash
mkdir -p /tmp/abe-lsss-cp
cd /tmp/abe-lsss-cp
printf 'Confidential project report\n' > report.txt

/path/to/abe-lsss/build/cli/abe-setup -s CP -p org
/path/to/abe-lsss/build/cli/abe-keygen -s CP -p org \
  -i 'Engineering|ProjectA' -o alice
/path/to/abe-lsss/build/cli/abe-encrypt -s CP -p org \
  -e '(Engineering and ProjectA)' -i report.txt -o report
/path/to/abe-lsss/build/cli/abe-decrypt -s CP -p org \
  -k alice.key -i report.cpabe -o recovered.txt
cmp report.txt recovered.txt
```

## KP-ABE example

In KP-ABE, the user's key carries the policy and each ciphertext carries its attributes:

```bash
mkdir -p /tmp/abe-lsss-kp
cd /tmp/abe-lsss-kp
printf 'Metadata-tagged record\n' > record.txt

/path/to/abe-lsss/build/cli/abe-setup -s KP -p archive
/path/to/abe-lsss/build/cli/abe-keygen -s KP -p archive \
  -i '(Engineering and (ProjectA or ProjectB))' -o auditor
/path/to/abe-lsss/build/cli/abe-encrypt -s KP -p archive \
  -e 'Engineering|ProjectA' -i record.txt -o record
/path/to/abe-lsss/build/cli/abe-decrypt -s KP -p archive \
  -k auditor.key -i record.kpabe -o recovered.txt
cmp record.txt recovered.txt
```

The parser accepts monotone AND/OR policies and supports tested date/integer expressions. See [`cli/POLICY.md`](../cli/POLICY.md) and [`cli/abe-policy-examples.txt`](../cli/abe-policy-examples.txt) for examples. A parsed expression should still be checked against the supported policy model; the presence of parser syntax does not establish non-monotone ABE support.

## File and security notes

- The CLI wraps serialized keys and parameters in labeled text blocks and base64-encodes the content; ciphertexts are similarly armored.
- Protect and securely provision the master secret file. Do not place it in source control or send it with ciphertexts.
- Use a fresh output name or directory for each run to avoid accidentally overwriting keys or ciphertexts.
- Treat the tools as experimental. There is no authenticated CCA ABE mode in the current CLI.
- The currently disabled `PK` command branches print a maintenance message; the active quick-start scope is CP/KP ABE.

For the C++ interface and its current packaging limitations, see the [API guide](API.md).
