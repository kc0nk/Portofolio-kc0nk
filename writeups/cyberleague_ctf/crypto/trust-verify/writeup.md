# Trust Verify — Writeup

> **Kategori:** Cryptography  
> **Teknik:** Schnorr Identification / Fiat–Shamir Forgery, Modular Arithmetic  
> **Target:** `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30007`  
> **Format Flag:** `CYBERLEAGUE{...}`

---

## 1. Deskripsi Challenge

**Trust Verify** adalah challenge cryptography yang menyediakan gateway autentikasi passwordless berbasis protokol identitas buatan sendiri.

Deskripsi:

```text
TrustVerify Inc. is rolling out a passwordless login gateway built on an identity protocol they commissioned themselves. Their launch copy calls it bulletproof and invites anyone to try it. The staging endpoint is still reachable.

Connect, inspect the handshake it offers, and submit a valid authentication proof for the privileged action it asks for. Get one accepted and the gateway hands over the flag.
```

Service:

```bash
nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30007
```

Tujuan challenge adalah membuat proof autentikasi yang diterima server untuk action:

```text
grant_admin_access
```

---

# 2. Reconnaissance

Saat terhubung ke service, server memberikan parameter:

```text
=== TrustVerify Authentication Gateway v2.1 ===
Session: 29ebd7a904d1b169

p = 124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084052418328789801603255015359491668501490376538831393608010563757657355916891875480779838581542527143058497444720815678032701548668767040003498600578212815699
q = 62162669573444692270247045542728315004928441370936403090865639509245910400059730011183701884897504125010595883791711610739592804533029613150625083582042026209164394900801627507679745834250745188269415696804005281878828677958445937740389919290771263571529248722360407839016350774334383520001749300289106407849
g = 2
y = 66114157759002164253156829525672161319419827235444764446926002995819476212546069155849867018286275071853253287498837340439750398934629965122337428497025285273350164917903854637643424064769066469930933521436022081273064109875466660803841595589928788826844775443117617958640646086908356309518267053037351757688
Submit a valid authentication proof for the requested action.
Action: b'grant_admin_access'

R =
```

Parameter tersebut sangat khas untuk **Schnorr-like identification**:

- `p` = modulus
- `q` = order subgroup
- `g` = generator
- `y` = public key
- `x` = private key yang tidak diketahui attacker

Relasi public key:

\[
y=g^x\pmod p
\]

---

# 3. Identifikasi Skema

Pada Schnorr, prover normalnya melakukan:

1. Pilih nonce `k`.
2. Hitung commitment:

\[
R=g^k\pmod p
\]

3. Dapatkan challenge `c`.
4. Hitung response:

\[
z=k+cx\pmod q
\]

5. Verifier memeriksa:

\[
g^z\stackrel{?}{=}R\,y^c\pmod p
\]

Karena:

\[
g^{k+cx}=g^k(g^x)^c=R\,y^c
\]

maka proof valid.

---

# 4. Vulnerability

Implementasi challenge melakukan hashing terhadap **message saja**:

```python
c = H(msg) % q
```

Padahal pada Fiat–Shamir Schnorr yang benar, commitment `R` harus masuk ke hash:

```python
c = H(R || msg) % q
```

Perbedaan ini sangat penting.

## Implementasi rentan

```text
message
   │
   ▼
H(message)
   │
   ▼
   c
```

Karena `c` tidak bergantung pada `R`, attacker dapat menghitung `c` terlebih dahulu.

## Implementasi yang seharusnya

```text
R + message
      │
      ▼
     H()
      │
      ▼
      c
```

Pada desain yang benar, verifier mengikat commitment dan challenge sehingga attacker tidak bisa memilih `R` setelah mengetahui `c`.

---

# 5. Menurunkan Forgery

Verifier memeriksa:

\[
g^z=R\,y^c\pmod p
\]

Kita cukup membalik persamaan tersebut terhadap `R`:

\[
R=g^z(y^c)^{-1}\pmod p
\]

atau ekuivalen:

\[
R=g^z y^{-c}\pmod p
\]

Artinya attacker dapat memilih `z` sembarang dan kemudian menghitung `R` yang membuat equality verifier pasti benar.

Tidak ada kebutuhan untuk mengetahui private key `x`.

---

# 6. Bukti Matematis

Pilih:

\[
z=1
\]

maka:

\[
R=g\,y^{-c}\pmod p
\]

Verifier menghitung sisi kanan:

\[
R\,y^c
\]

Substitusikan `R`:

\[
(g y^{-c})y^c
\]

Sehingga:

\[
gy^{-c}y^c=g
\]

Sedangkan sisi kiri:

\[
g^z=g^1=g
\]

Jadi:

\[
g^z=R\,y^c
\]

**secara konstruktif selalu benar**.

Dengan demikian proof dapat diforge tanpa memecahkan discrete logarithm.

---

# 7. Menghitung Challenge

Action yang diberikan server:

```python
b'grant_admin_access'
```

Challenge dihitung sebagai:

```python
c = int(
    hashlib.sha256(action).hexdigest(),
    16
) % q
```

Pada sesi berhasil:

```text
c = 112802833962047968603000343407199713251827615673074980546504641483296633752884
```

---

# 8. Memilih Response `z`

Karena `z` tidak dibatasi oleh secret yang kita miliki, kita dapat memilih nilai sederhana:

```python
z = 1
```

Tidak dibutuhkan brute force.

---

# 9. Membuat Forged Commitment `R`

Gunakan:

```python
R = (
    pow(g, z, p)
    * pow(y, -c, p)
) % p
```

`pow(y, -c, p)` memanfaatkan modular exponentiation Python untuk menghitung inverse modular pada modulus `p`.

Secara ekuivalen dapat ditulis:

```python
yc = pow(y, c, p)
yc_inv = pow(yc, -1, p)
R = (pow(g, z, p) * yc_inv) % p
```

---

# 10. Sanity Check Lokal

Sebelum mengirim proof, cek verifier secara lokal:

```python
lhs = pow(g, z, p)
rhs = (R * pow(y, c, p)) % p
assert lhs == rhs
```

Jika assertion berhasil, proof yang kita bentuk memang memenuhi persamaan verifier.

---

# 11. Exploit Chain

```text
Connect
  │
  ▼
Parse p, q, g, y
  │
  ▼
Parse Action
  │
  ▼
c = SHA256(Action) mod q
  │
  ▼
Pilih z = 1
  │
  ▼
R = g^z × y^(-c) mod p
  │
  ▼
Sanity check
  │
  ▼
Kirim R
  │
  ▼
Kirim z
  │
  ▼
Verifier menerima
  │
  ▼
Proof verified!
  │
  ▼
Flag
```

---

# 12. Solver Python

Berikut solver otomatis untuk terhubung ke service, membaca parameter, membuat forgery, dan mengambil flag.

```python
#!/usr/bin/env python3

from pwn import *
import hashlib
import re

HOST = (
    "cyberleague-shared-nlb-8eebe55"
    ".elb.ap-southeast-1.amazonaws.com"
)
PORT = 30007

# Perbaiki hostname sesuai target sebenarnya.
HOST = (
    "cyberleague-shared-nlb-8eebe09f116ebe55"
    ".elb.ap-southeast-1.amazonaws.com"
)


def parse_value(banner, name):
    m = re.search(
        rb"(?m)^" + re.escape(name.encode()) + rb"\s*=\s*([0-9]+)",
        banner,
    )
    if not m:
        raise ValueError(f"{name} tidak ditemukan")
    return int(m.group(1))


def parse_action(banner):
    m = re.search(
        rb"Action:\s*b['\"]([^'\"]+)['\"]",
        banner,
    )
    if not m:
        raise ValueError("Action tidak ditemukan")
    return m.group(1)


def main():
    io = remote(HOST, PORT)

    banner = io.recvuntil(b"R =\n")
    print(banner.decode(errors="replace"))

    p = parse_value(banner, "p")
    q = parse_value(banner, "q")
    g = parse_value(banner, "g")
    y = parse_value(banner, "y")
    action = parse_action(banner)

    log.info(f"p = {p}")
    log.info(f"q = {q}")
    log.info(f"g = {g}")
    log.info(f"y = {y}")
    log.info(f"action = {action!r}")

    # c = SHA256(message) mod q
    digest = hashlib.sha256(action).digest()
    h = int.from_bytes(digest, "big")
    c = h % q

    log.success(f"c = {c}")

    # Pilih z bebas.
    z = 1

    # Forgery:
    # R = g^z * y^(-c) mod p
    R = (
        pow(g, z, p)
        * pow(y, -c, p)
    ) % p

    log.success(f"Forged R = {R}")
    log.info(f"Chosen z = {z}")

    # Verifikasi lokal.
    lhs = pow(g, z, p)
    rhs = (R * pow(y, c, p)) % p

    if lhs != rhs:
        log.failure("Forgery tidak valid")
        io.close()
        return

    log.success(
        "Sanity check lokal: lhs == rhs, forgery valid."
    )

    # Kirim proof.
    io.sendline(str(R).encode())
    io.sendline(str(z).encode())

    result = io.recvall(timeout=5)
    print(result.decode(errors="replace"))

    io.close()


if __name__ == "__main__":
    main()
```

> **Catatan:** hostname pada blok solver mengikuti endpoint challenge yang diberikan. Baris assignment kedua hanya dibuat eksplisit agar hostname target lengkap terbaca jelas.

---

# 13. Versi Exploit Minimal

Jika parameter sudah diparsing manual, inti exploit hanya beberapa baris:

```python
from hashlib import sha256

c = int.from_bytes(
    sha256(action).digest(),
    "big"
) % q

z = 1

R = (
    pow(g, z, p)
    * pow(y, -c, p)
) % p

assert (
    pow(g, z, p)
    == (R * pow(y, c, p)) % p
)
```

Inilah primitive exploit yang paling penting dari challenge.

---

# 14. Output Verifikasi

Sesi exploit yang berhasil menghasilkan:

```text
[*] g = 2
[*] y = 89315281553162050916668048030623562939820084790206299061023666768754618305009525292314321744826563533240384373996989682565095385749915690448893988981842031033869349341684550665486268323294103210545202535449031373528034681091148944001147971281836562640276890821582307218812881854412011561895876615924937399036
[*] action = b'grant_admin_access'
[*] c = 112802833962047968603000343407199713251827615673074980546504641483296633752884
[*] Forged R = 113570007880667534405528122611641852204597896060419294774808240670732222089874261057274251035378570456479014385538557427887022298819127345411384388201358562135997365809954862704927781692967467295924116635788640539486810551625035652962169035509723253093261694775496217293454878677506127409142136545900549669879
[*] Chosen z = 1
[+] Sanity check lokal: lhs == rhs, forgery valid.
[+] Receiving all data: Done (63B)
[*] Closed connection to cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com port 30007
Proof verified!
CYBERLEAGUE{tr5t_v3r1fy_z3r0_kn0wl3dg3_f0rg3d}

[+] FLAG DITEMUKAN: CYBERLEAGUE{tr5t_v3r1fy_z3r0_kn0wl3dg3_f0rg3d}
```

---

# 15. Kenapa Attack Ini Berhasil?

Serangan bekerja karena attacker mengetahui `c` **sebelum** commitment `R` dibatasi oleh verifier.

Pada desain rusak:

```text
message
  ↓
SHA256
  ↓
 c
```

kemudian attacker dapat melakukan:

```text
pilih z
  ↓
R = g^z y^(-c)
```

Sedangkan pada Schnorr/Fiat–Shamir yang benar:

```text
R + message
     ↓
   SHA256
     ↓
      c
```

Attacker tidak dapat memilih `R` secara bebas setelah mengetahui `c`.

---

# 16. Tidak Perlu Recover Private Key

Private key memenuhi:

\[
y=g^x\pmod p
\]

Secara umum menemukan `x` dari `y` adalah discrete logarithm problem.

Namun challenge tidak perlu memecahkan:

```text
x = log_g(y)
```

karena forgery langsung menggunakan public value `y`:

\[
R=g^z y^{-c}\pmod p
\]

Jadi exploit-nya adalah **proof forgery**, bukan private-key recovery.

---

# 17. Bukan Nonce-Reuse Attack

Challenge ini juga berbeda dari serangan ECDSA seperti:

```text
nonce reuse
biased nonce
HNP
```

Tidak ada signature yang perlu dikumpulkan.

Tidak ada lattice.

Tidak ada discrete logarithm.

Kita cukup mengeksploitasi kesalahan desain verifier.

---

# 18. Tooling

Tool yang dibutuhkan sangat minimal:

```text
Python 3
hashlib
pwntools
```

Tidak diperlukan:

```text
SageMath
RsaCtfTool
PyCryptodome
fpylll
```

Untuk aritmetika modular, Python sudah menyediakan:

```python
pow(base, exp, mod)
```

termasuk modular inverse dengan eksponen negatif pada Python modern.

---

# 19. Root Cause

Kerentanan utama adalah **Missing Fiat–Shamir Commitment Binding**.

Implementasi rentan:

```python
c = H(msg) % q
```

Implementasi yang benar:

```python
c = H(R || msg) % q
```

Akibatnya:

```text
commitment R
      │
      X   ← tidak ikut dalam hash
      │
challenge c
```

Attacker dapat memilih `R` setelah mengetahui `c`, yang membuat verifier dapat dibalik secara aljabar.

---

# 20. Impact

Jika desain seperti ini digunakan pada autentikasi nyata, penyerang yang mengetahui public parameter dapat membuat proof yang diterima verifier tanpa mengetahui secret.

Dalam konteks challenge, impact-nya adalah:

```text
Unauthorized authentication
        ↓
grant_admin_access
        ↓
Proof verified!
        ↓
Flag disclosure
```

---

# 21. Lessons Learned

## 21.1. Audit verifier, bukan hanya primitive

Cryptographic primitive yang benar tidak menjamin protokol implementasinya benar.

Pada challenge ini, Schnorr sendiri bukan masalah utama. Kesalahan terjadi pada pembentukan challenge.

## 21.2. Commitment harus mengikat challenge

Pada Fiat–Shamir, bentuk umum yang aman adalah mengikat setidaknya:

```text
commitment
+
message / context
```

ke hash challenge.

## 21.3. Cari persamaan yang bisa dibalik

Saat melihat verifier:

```python
lhs == rhs
```

coba periksa apakah salah satu variabel dapat direkayasa agar equality selalu benar.

Di sini:

\[
R= g^z y^{-c}
\]

langsung menyelesaikan problem.

---

# 22. Solve Chain Singkat

```text
nc target
   │
   ▼
Ambil p, q, g, y
   │
   ▼
Action = grant_admin_access
   │
   ▼
c = SHA256(Action) mod q
   │
   ▼
Pilih z = 1
   │
   ▼
R = g × y^(-c) mod p
   │
   ▼
Local sanity check
   │
   ▼
Submit R, z
   │
   ▼
Proof verified!
   │
   ▼
FLAG
```

---

# 23. Ringkasan

| Komponen | Nilai |
|---|---|
| Scheme | Schnorr-like identification |
| Modulus | `p` |
| Subgroup order | `q` |
| Generator | `g = 2` |
| Public key | `y = g^x mod p` |
| Challenge | `SHA256(message) mod q` |
| Seharusnya | `SHA256(R || message) mod q` |
| Vulnerability | Missing commitment binding |
| Attack | Schnorr proof forgery |
| Pilihan `z` | `1` |
| Forged commitment | `R = g^z y^(-c) mod p` |
| Private key diperlukan | Tidak |
| Lattice diperlukan | Tidak |
| Flag | `CYBERLEAGUE{tr5t_v3r1fy_z3r0_kn0wl3dg3_f0rg3d}` |

---

# 24. Flag

```text
CYBERLEAGUE{tr5t_v3r1fy_z3r0_kn0wl3dg3_f0rg3d}
```

---

## Referensi

Shared analysis:

```text
https://claude.ai/share/a4968601-4616-44f7-aec4-2183ec4e4599
```

> Writeup ini disusun berdasarkan analisis dan hasil verifikasi yang terdapat pada shared conversation tersebut. Detail attack mengikuti implementasi verifier yang dijelaskan di sana: challenge `c` tidak mengikat commitment `R`, sehingga `R` dapat direkayasa secara langsung untuk menghasilkan proof yang valid.
