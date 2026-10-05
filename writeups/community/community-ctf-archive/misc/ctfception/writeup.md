# Null0rigin CTF 2026 — CTFception Writeup

## Challenge

**Name:** CTFception  
**Category:** Forensics / Crypto / OSINT / Misc  
**Target:** `https://ctfception.onrender.com/`

> Every archive hides another archive.  
> A clandestine carrier signal transmitting at 25.09 MHz has been intercepted from an encrypted historical vault dedicated to Lokmanya Tilak and preserved by PRX02.  
> Can you investigate the platform, crack the vault, and reconstruct the lost transmission?  
>
> “Some stories survive because someone keeps telling them.”

---

## Overview

This challenge is a small multi-stage chain:

```text
Web platform
   ↓
Encrypted ZIP archive
   ↓
Historical password clue
   ↓
Dispatch note
   ↓
Base64 + repeating-key XOR
   ↓
Beacon reconstruction key
   ↓
Built-in web terminal
   ↓
Final flag
```

The challenge mixes historical OSINT with light cryptography and file analysis.

---

# 1. Explore the CTFception Platform

The site presents an archive-themed interface and a built-in web terminal.

The important archive is:

```text
kesari_vault_1908.zip
```

Download it and inspect it locally.

```bash
file kesari_vault_1908.zip
7z l kesari_vault_1908.zip
```

Output showed:

```text
Type = zip
Physical Size = 2320

MANDALAY_DISPATCH_1908.txt
beacon_payload.enc
telegraph_decoder.py
```

The ZIP was AES encrypted.

---

# 2. Recover the ZIP Password

The challenge theme points directly toward Lokmanya Bal Gangadhar Tilak.

One of the strongest historical clues is his work:

```text
Gita Rahasya
```

Tilak wrote *Shrimadh Bhagavad Gita Rahasya* during his imprisonment in Mandalay.

A small candidate list was tested against the ZIP:

```bash
cat > /tmp/passes.txt <<'EOF'
Gita Rahasya
GitaRahasya
gitarahasya
GITARAHASYA
Gita_Rahasya
gita_rahasya
Shrimad Bhagavad Gita Rahasya
ShrimadBhagavadGitaRahasya
shrimadbhagavadgitarahasya
Shrimadh Bhagavad Gita Rahasya
ShrimadhBhagavadGitaRahasya
shrimadhbhagavadgitarahasya
Srimad Bhagavad Gita Rahasya
SrimadBhagavadGitaRahasya
srimadbhagavadgitarahasya
EOF

while IFS= read -r p; do
    if 7z t kesari_vault_1908.zip -p"$p" >/dev/null 2>&1; then
        echo "[+] PASSWORD FOUND: $p"
        break
    else
        echo "[-] $p"
    fi
done < /tmp/passes.txt
```

The correct password was:

```text
gitarahasya
```

---

# 3. Extract the Vault

Extract the archive:

```bash
7z x kesari_vault_1908.zip -p'gitarahasya' -oKesariVault
cd KesariVault
ls -lah
```

Files recovered:

```text
MANDALAY_DISPATCH_1908.txt
beacon_payload.enc
telegraph_decoder.py
```

---

# 4. Read the Mandalay Dispatch

Inspect the note:

```bash
cat MANDALAY_DISPATCH_1908.txt
```

The most important section was:

```text
The telegraph cipher was keyed using the date of the upcoming eternal chronicle:

Day and Month: 25th Sept -> Key: '2509'

To reconstruct the final archival record:

1. Decode 'beacon_payload.enc' using telegraph_decoder.py
   with the chronicle key '2509'.

2. Enter the resulting beacon phrase into the CTFception Web Terminal using:

   reconstruct <DECODED_BEACON_KEY>
```

This tells us the next cryptographic key directly:

```text
2509
```

The challenge description also references a carrier signal at:

```text
25.09 MHz
```

which reinforces the same `2509` clue.

---

# 5. Analyze the Decoder

Inspect the supplied script before running it:

```bash
cat telegraph_decoder.py
```

The relevant logic was:

```python
import base64

def decode_payload(payload_path, key):
    with open(payload_path, "r") as f:
        encoded_str = f.read().strip()

    data = base64.b64decode(encoded_str)

    key_bytes = key.encode("utf-8")

    decoded = bytes([
        b ^ key_bytes[i % len(key_bytes)]
        for i, b in enumerate(data)
    ])

    return decoded.decode("utf-8")
```

So the algorithm is:

```text
Base64 decode
     ↓
Repeating-key XOR
     ↓
Key = "2509"
```

---

# 6. Inspect the Encrypted Beacon

View the payload:

```bash
xxd -g 1 beacon_payload.enc
```

The file contained:

```text
fnp7dHN7aXhtcnFtenRvenpnf3d7dnx8bQQJCQo=
```

This is Base64 text.

The supplied decoder can be executed directly:

```bash
python3 telegraph_decoder.py 2509
```

The recovered beacon phrase was:

```text
LOKMANYA_GATHA_CHRONICLE_1908
```

---

# 7. Reconstruct the Final Record

The challenge now instructs us to use the **built-in CTFception web terminal**.

Important: this command is entered inside the challenge website terminal, **not** in the browser DevTools console and **not** in Kali.

Enter:

```text
reconstruct LOKMANYA_GATHA_CHRONICLE_1908
```

The platform then reconstructs the final archival record and reveals the challenge flag.

---

# Complete Solve Chain

```text
ctfception.onrender.com
        ↓
kesari_vault_1908.zip
        ↓
Password:
gitarahasya
        ↓
MANDALAY_DISPATCH_1908.txt
        ↓
Chronicle key:
2509
        ↓
beacon_payload.enc
        ↓
Base64 decode
        ↓
Repeating XOR using "2509"
        ↓
LOKMANYA_GATHA_CHRONICLE_1908
        ↓
Web terminal:
reconstruct LOKMANYA_GATHA_CHRONICLE_1908
        ↓
Final flag
```

---

# Useful Commands

## Inspect archive

```bash
file kesari_vault_1908.zip
7z l kesari_vault_1908.zip
```

## Extract

```bash
7z x kesari_vault_1908.zip -p'gitarahasya' -oKesariVault
```

## Read evidence

```bash
cd KesariVault

cat MANDALAY_DISPATCH_1908.txt
cat telegraph_decoder.py
xxd -g 1 beacon_payload.enc
```

## Decode beacon

```bash
python3 telegraph_decoder.py 2509
```

Expected result:

```text
LOKMANYA_GATHA_CHRONICLE_1908
```

## Final platform command

```text
reconstruct LOKMANYA_GATHA_CHRONICLE_1908
```

---

# Why the Challenge Works

The challenge hides each next step behind a different type of clue:

- **Historical OSINT** identifies the archive password.
- **Filesystem inspection** reveals the included dispatch and decoder.
- **Challenge lore** provides the XOR key.
- **Base64 + XOR** reconstructs the beacon.
- **The web terminal** performs the final stage.

The phrase:

> “Every archive hides another archive.”

is therefore less about literal recursive ZIP files and more about layers of information: each recovered artifact points toward the next.

---

# Key Takeaways

- Read challenge lore carefully; dates and historical names can be cryptographic clues.
- Do not brute-force blindly when the challenge gives contextual hints.
- Always inspect supplied decoder scripts before executing them.
- Base64 is encoding, not encryption.
- Repeating-key XOR is easy to reverse once the key is known.
- Built-in web terminals may be part of the intended solve path rather than ordinary system shells.

---

# Recovered Intermediate Values

```text
ZIP password:
gitarahasya

Chronicle key:
2509

Decoded beacon:
LOKMANYA_GATHA_CHRONICLE_1908

Final terminal command:
reconstruct LOKMANYA_GATHA_CHRONICLE_1908
```

---

## Final Flag

The final flag was revealed by the CTFception web terminal after the reconstruction command.

```text
Null0rigin{<final_flag_from_terminal>}
```

The exact flag text is intentionally left as the value obtained from the live challenge terminal.
