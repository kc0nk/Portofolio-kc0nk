# Embassy Cables — Writeup

> **Kategori:** Cryptography  
> **Teknik:** ECDSA, Biased Nonce, Hidden Number Problem (HNP), Lattice Reduction / LLL  
> **Target:** `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30006`  
> **Format Flag:** `CYBERLEAGUE{...}`

---

## 1. Deskripsi Challenge

Challenge **Embassy Cables** memberikan akses ke sebuah terminal komunikasi diplomatik yang menggunakan **ECDSA** untuk menandatangani setiap kabel keluar.

Deskripsi challenge:

```text
You have a tap on the secure channel of a foreign embassy. Their relay hums along quietly signing every outbound dispatch before it leaves the compound, and it will happily sign anything you hand it. The implementation cleared an internal audit last quarter and nobody has looked at it since.

Connect, collect signed cables, and recover the ambassador's private signing key.
```

Service yang disediakan:

```bash
nc cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com 30006
```

Saat terhubung, server memberikan public key:

```text
pubkey_x = 0xf02bf0529f408b66e6fbfbb9b3becbee874d602cb4911dc8adb8016f3a0e5e12
pubkey_y = 0xd237a763d8afbeb2289b4cd1d2b3a6a0695c918d1674bfd3059a6883f7f2d43e
```

dan:

```text
Session authenticated. 25 operations remaining.
Commands: SIGN | SUBMIT | EXIT
```

Tujuan akhirnya adalah memperoleh private key ECDSA milik ambassador dan mengirimkannya melalui:

```text
SUBMIT
```

---

# 2. Eksplorasi Awal

Percobaan manual dengan `nc` menunjukkan bahwa server bukan shell.

Contoh:

```text
TERMINAL> ls
ERROR: unknown command

TERMINAL> id
ERROR: unknown command
```

Command yang valid hanya:

```text
SIGN
SUBMIT
EXIT
```

Untuk `SIGN`, server meminta:

```text
cable_content_hex:
```

Input harus berupa hexadecimal valid.

Contoh input salah:

```text
12121
```

menghasilkan:

```text
ERROR: invalid hex encoding
```

karena jumlah digit hexadecimal harus genap.

Untuk `SUBMIT`, server meminta:

```text
ambassador_key_hex:
```

yang juga harus berupa hexadecimal.

Jadi server memang dirancang sebagai **signing oracle** dan **private-key submission endpoint**.

---

# 3. Identifikasi Algoritma

Dari public key dan implementasi challenge, algoritma yang digunakan adalah:

```text
ECDSA
```

pada kurva:

```text
secp256k1
```

ECDSA menggunakan parameter:

```text
Private key : d
Public key  : Q = dG
Nonce       : k
```

Untuk sebuah pesan dengan hash `h`, signature terdiri dari:

```text
(r, s)
```

dengan persamaan:

\[
r = x(kG) \bmod n
\]

dan:

\[
s = k^{-1}(h + rd)\bmod n
\]

di mana:

- `d` = private key yang ingin ditemukan
- `k` = nonce
- `h` = message hash
- `n` = order kurva
- `G` = generator secp256k1

Secara normal, keamanan ECDSA sangat bergantung pada nonce `k` yang benar-benar acak dan sulit diprediksi.

---

# 4. Menemukan Vulnerability

Bagian paling penting terdapat pada implementasi generator nonce:

```python
ENTROPY_SOURCE_BITS = 256
HASH_TRUNCATION     = 16

EFFECTIVE_BITS = (
    ENTROPY_SOURCE_BITS
    - HASH_TRUNCATION
)
```

Sehingga:

```text
EFFECTIVE_BITS = 240
```

Kemudian nonce dibentuk:

```python
raw = self.generate_entropy(
    self.EFFECTIVE_BITS
)

k = int.from_bytes(
    raw,
    "big"
) % order
```

Masalahnya adalah nonce hanya memiliki:

```text
240 bit entropy
```

sedangkan order `secp256k1` kira-kira:

```text
2^256
```

Karena:

\[
2^{240} \ll n
\]

maka operasi:

```python
% order
```

tidak memperbesar ruang nilai nonce.

Dengan kata lain:

\[
0 \le k < 2^{240}
\]

Artinya **16 bit paling signifikan nonce selalu nol**.

---

# 5. Kenapa Ini Fatal?

ECDSA mengasumsikan nonce `k` sulit diketahui.

Namun challenge menghasilkan:

```text
k < 2^240
```

padahal normalnya:

```text
k < 2^256
```

Kita mengetahui bahwa nonce memiliki batas atas:

\[
B = 2^{240}
\]

Jadi kita tidak mengetahui nilai `k` secara langsung, tetapi kita mengetahui bahwa:

\[
k_i < B
\]

untuk setiap signature.

Informasi parsial semacam ini cukup untuk mengubah masalah menjadi **Hidden Number Problem (HNP)**.

Teknik umum untuk menyelesaikannya adalah:

```text
HNP
 ↓
Lattice construction
 ↓
LLL
 ↓
Recover private key
```

---

# 6. Menurunkan Persamaan ECDSA

Rumus ECDSA:

\[
s_i = k_i^{-1}(h_i+r_i d)\pmod n
\]

Kalikan kedua sisi dengan `k_i`:

\[
s_i k_i \equiv h_i+r_i d \pmod n
\]

Kalikan dengan invers `s_i`:

\[
k_i \equiv h_i s_i^{-1}+r_i s_i^{-1}d\pmod n
\]

Definisikan:

\[
a_i=h_i s_i^{-1}\pmod n
\]

dan:

\[
t_i=r_i s_i^{-1}\pmod n
\]

Maka:

\[
k_i\equiv a_i+t_i d\pmod n
\]

Karena kita tahu:

\[
0\le k_i<B
\]

kita memiliki persamaan:

\[
k_i=a_i+t_i d+nq_i
\]

untuk suatu integer `q_i`.

Inilah bentuk HNP yang ingin kita selesaikan.

---

# 7. Kenapa 24 Signature?

Server memberikan:

```text
25 operations remaining
```

Kita membutuhkan satu operasi terakhir untuk:

```text
SUBMIT
```

Maka jumlah maksimal signature:

```text
24
```

Kita gunakan:

```text
24 SIGN
1 SUBMIT
```

Dengan bias:

```text
16 bit/signature
```

jumlah sample tersebut sudah cukup untuk membuat lattice mempunyai constraint yang kuat.

Secara intuisi:

```text
1 signature  -> informasi terbatas
beberapa signature -> constraint mulai saling mengikat
24 signatures -> cukup untuk LLL menemukan private key
```

---

# 8. Formulasi Lattice

Diketahui:

\[
k_i=a_i+t_i d+nq_i
\]

Kita ingin menghasilkan sebuah vektor lattice pendek yang berisi:

\[
(nk_1,nk_2,\ldots,nk_m,dB,nB)
\]

untuk:

```text
m = 24
B = 2^240
```

Gunakan lattice berdimensi:

\[
m+2=26
\]

Basis integer yang digunakan:

```text
Row i (0 <= i < m):
    n² pada diagonal

Row m:
    n*t_1, n*t_2, ..., n*t_m, B, 0

Row m+1:
    n*a_1, n*a_2, ..., n*a_m, 0, n*B
```

Secara matriks:

\[
M=
\begin{pmatrix}
n^2 & 0 & \cdots & 0 & 0 & 0\\
0 & n^2 & \cdots & 0 & 0 & 0\\
\vdots & & \ddots & & \vdots & \vdots\\
0 & 0 & \cdots & n^2 & 0 & 0\\
nt_1 & nt_2 & \cdots & nt_m & B & 0\\
na_1 & na_2 & \cdots & na_m & 0 & nB
\end{pmatrix}
\]

Ambil kombinasi baris dengan koefisien:

```text
q_1, q_2, ..., q_m, d, 1
```

maka koordinat pertama menjadi:

\[
n^2q_i+nt_i d+na_i
\]

atau:

\[
n(nq_i+t_i d+a_i)
\]

yang sama dengan:

\[
nk_i
\]

sehingga terbentuk:

\[
(nk_1,\ldots,nk_m,dB,nB)
\]

Karena:

\[
k_i<B
\]

vektor tersebut memiliki struktur khusus yang dapat ditemukan oleh **LLL**.

---

# 9. LLL

LLL (Lenstra–Lenstra–Lovász) adalah algoritma lattice reduction yang digunakan untuk menemukan basis yang lebih pendek.

Pada challenge ini kita tidak perlu menjalankan brute force terhadap:

```text
2^256
```

atau bahkan:

```text
2^240
```

untuk setiap nonce.

Sebaliknya, LLL memanfaatkan relasi matematis dari **24 signature sekaligus**.

Secara umum:

```text
Signature #1 ─┐
Signature #2 ─┤
Signature #3 ─┤
       ...     ├──> Lattice
Signature #24 ─┘
                  │
                  ▼
                 LLL
                  │
                  ▼
             short vectors
                  │
                  ▼
           private key candidate
```

---

# 10. Ekstraksi Private Key

Dari vector hasil LLL yang sesuai:

```text
v[-1] = ± nB
```

koordinat kedua dari belakang memiliki bentuk:

```text
± dB
```

Maka:

\[
d=\frac{v_{m}}{B}
\]

dengan penyesuaian tanda ketika seluruh vektor ditemukan dalam bentuk negatif.

Setelah kandidat `d` diperoleh, kita harus melakukan verifikasi:

\[
Q=dG
\]

dan membandingkannya dengan public key yang diberikan server.

Ini sangat penting karena hasil LLL belum tentu langsung memberikan vector target pada basis pertama.

---

# 11. Verifikasi Public Key

Public key dari server:

```text
x =
f02bf0529f408b66e6fbfbb9b3becbee874d602cb4911dc8adb8016f3a0e5e12

y =
d237a763d8afbeb2289b4cd1d2b3a6a0695c918d1674bfd3059a6883f7f2d43e
```

Setelah private key ditemukan, verifikasi:

```python
d * G == Q
```

atau menggunakan library `ecdsa`.

Jika cocok:

```text
[+] Private key valid
```

baru key dikirim ke server.

---

# 12. Solver Workflow

Solver otomatis melakukan:

```text
1. Connect ke service
2. Ambil public key
3. SIGN sebanyak 24 kali
4. Parse r, s, h
5. Hitung a_i dan t_i
6. Bangun lattice 26 x 26
7. Jalankan LLL
8. Scan kandidat private key
9. Verifikasi d*G == public key
10. SUBMIT private key
11. Ambil flag
```

---

# 13. Dependensi

Versi Python:

```bash
python3 --version
```

Dependensi:

```bash
pip install pwntools ecdsa fpylll
```

Jika menggunakan Arch Linux dan `fpylll` mengalami masalah build, gunakan SageMath sebagai alternatif untuk operasi LLL.

Untuk `fpylll`, masalah umum berasal dari dependensi matematika seperti:

```text
GMP
MPFR
```

---

# 14. Solver Python

Berikut solver yang mengotomatisasi pengambilan 24 signature, HNP lattice attack, verifikasi public key, dan `SUBMIT`.

```python
#!/usr/bin/env python3

from pwn import *
from ecdsa import curves, ellipticcurve
from fpylll import IntegerMatrix, LLL
import re
import sys


# ============================================================
# Configuration
# ============================================================

HOST = (
    "cyberleague-shared-nlb-8eebe09f116ebe55"
    ".elb.ap-southeast-1.amazonaws.com"
)

PORT = 30006

NUM_SIGS = 24

# secp256k1 order
N = int(curves.SECP256k1.order)

# Nonce bound:
# 240 effective random bits
BOUND = 1 << 240


# Public key supplied by the challenge
PUB_X = int(
    "f02bf0529f408b66e6fbfbb9b3becbee"
    "874d602cb4911dc8adb8016f3a0e5e12",
    16
)

PUB_Y = int(
    "d237a763d8afbeb2289b4cd1d2b3a6a"
    "0695c918d1674bfd3059a6883f7f2d43e",
    16
)


# ============================================================
# Connection
# ============================================================

def start():
    context.log_level = "info"

    io = remote(
        HOST,
        PORT
    )

    return io


# ============================================================
# Parse signature
# ============================================================

def parse_signature(data, message):
    """
    Accept several possible server output formats.

    Expected examples:

        r=123...
        s=456...
        h=789...

    or:

        r = 123...
        s = 456...
        h = 789...
    """

    text = data.decode(
        errors="replace"
    )

    def find(name):
        m = re.search(
            rf"\b{name}\s*=\s*(0x[0-9a-fA-F]+|\d+)",
            text
        )

        if not m:
            return None

        value = m.group(1)

        return int(
            value,
            0 if value.startswith("0x")
            else 10
        )

    r = find("r")
    s = find("s")
    h = find("h")

    if r is None or s is None:
        raise ValueError(
            "Tidak dapat mem-parse r/s:\n"
            + text
        )

    # Jika server tidak mengirim h,
    # hitung SHA-256 sendiri.
    if h is None:
        import hashlib

        digest = hashlib.sha256(
            message
        ).digest()

        h = int.from_bytes(
            digest,
            "big"
        )

    return r, s, h


# ============================================================
# Collect signatures
# ============================================================

def collect_signatures(io):
    signatures = []

    for i in range(NUM_SIGS):

        # Generate deterministic,
        # unique message.
        message = (
            f"cable-{i:04d}"
        ).encode()

        message_hex = message.hex().encode()

        log.info(
            f"[*] SIGN {i + 1}/{NUM_SIGS}"
        )

        io.sendlineafter(
            b"TERMINAL> ",
            b"SIGN"
        )

        io.sendlineafter(
            b"cable_content_hex: ",
            message_hex
        )

        data = io.recvuntil(
            b"TERMINAL> "
        )

        r, s, h = parse_signature(
            data,
            message
        )

        signatures.append(
            (r, s, h)
        )

        log.success(
            f"[+] sig {i + 1}: "
            f"r={r} "
            f"s={s} "
            f"h={h}"
        )

    return signatures


# ============================================================
# HNP parameters
# ============================================================

def build_hnp_parameters(
    signatures
):
    a = []
    t = []

    for r, s, h in signatures:

        s_inv = pow(
            s,
            -1,
            N
        )

        a_i = (
            h * s_inv
        ) % N

        t_i = (
            r * s_inv
        ) % N

        a.append(
            int(a_i)
        )

        t.append(
            int(t_i)
        )

    return a, t


# ============================================================
# Construct lattice
# ============================================================

def build_lattice(
    a,
    t
):
    m = len(a)

    dim = m + 2

    M = IntegerMatrix(
        dim,
        dim
    )

    # Clear matrix
    for i in range(dim):
        for j in range(dim):
            M[i, j] = 0

    # --------------------------------------------------------
    # n² diagonal
    # --------------------------------------------------------

    for i in range(m):
        M[i, i] = int(N) ** 2

    # --------------------------------------------------------
    # Row m
    # n*t_i ... B ... 0
    # --------------------------------------------------------

    for i in range(m):
        M[m, i] = int(N) * int(t[i])

    M[m, m] = int(BOUND)

    # --------------------------------------------------------
    # Row m+1
    # n*a_i ... 0 ... nB
    # --------------------------------------------------------

    for i in range(m):
        M[m + 1, i] = (
            int(N) * int(a[i])
        )

    M[m + 1, m] = 0

    M[m + 1, m + 1] = (
        int(N) * int(BOUND)
    )

    return M


# ============================================================
# Verify private key
# ============================================================

def verify_private_key(
    d
):
    d %= N

    G = curves.SECP256k1.generator

    point = (
        d * G
    )

    return (
        int(point.x())
        == PUB_X
        and
        int(point.y())
        == PUB_Y
    )


# ============================================================
# Recover private key
# ============================================================

def recover_private_key(
    reduced,
    a,
    t
):
    """
    Search reduced basis rows for the
    special embedded vector.

    Expected shape:

        (n*k1, ..., n*km, d*B, n*B)

    or the complete negative of it.
    """

    m = len(a)

    target_last = (
        int(N) * int(BOUND)
    )

    for row_index in range(
        reduced.nrows()
    ):

        row = [
            int(
                reduced[row_index, j]
            )
            for j in range(
                reduced.ncols()
            )
        ]

        last = row[-1]

        # Exact embedding marker.
        if abs(last) != target_last:
            continue

        d_scaled = row[-2]

        if last < 0:
            d_scaled = -d_scaled

        if d_scaled % BOUND != 0:
            continue

        candidate = (
            d_scaled // BOUND
        )

        candidate %= N

        log.info(
            "[*] Candidate from "
            f"LLL row {row_index}: "
            f"{candidate:#x}"
        )

        if verify_private_key(
            candidate
        ):
            return candidate

    return None


# ============================================================
# Alternative candidate extraction
# ============================================================

def try_candidates(
    reduced,
    signatures
):
    """
    More tolerant scan in case the target vector
    is returned with a different sign/orientation.

    This function searches rows whose final coordinate
    has the expected absolute magnitude and tests both signs.
    """

    target_last = (
        int(N) * int(BOUND)
    )

    for row_index in range(
        reduced.nrows()
    ):

        row = [
            int(
                reduced[
                    row_index,
                    j
                ]
            )
            for j in range(
                reduced.ncols()
            )
        ]

        if abs(row[-1]) != target_last:
            continue

        raw = row[-2]

        for sign in (
            1,
            -1
        ):

            value = sign * raw

            if value % BOUND:
                continue

            d = (
                value // BOUND
            ) % N

            if verify_private_key(
                d
            ):
                return d

    return None


# ============================================================
# Main
# ============================================================

def main():

    io = start()

    # --------------------------------------------------------
    # Receive initial banner
    # --------------------------------------------------------

    io.recvuntil(
        b"TERMINAL> "
    )

    # --------------------------------------------------------
    # Collect signatures
    # --------------------------------------------------------

    signatures = collect_signatures(
        io
    )

    log.success(
        f"[+] Collected "
        f"{len(signatures)} signatures"
    )

    # --------------------------------------------------------
    # HNP parameters
    # --------------------------------------------------------

    a, t = build_hnp_parameters(
        signatures
    )

    log.info(
        "[*] Building HNP lattice..."
    )

    # --------------------------------------------------------
    # Lattice
    # --------------------------------------------------------

    M = build_lattice(
        a,
        t
    )

    log.info(
        f"[*] Lattice dimension: "
        f"{M.nrows()} x {M.ncols()}"
    )

    # --------------------------------------------------------
    # LLL
    # --------------------------------------------------------

    log.info(
        "[*] Running LLL..."
    )

    LLL.reduction(
        M
    )

    log.success(
        "[+] LLL finished"
    )

    # --------------------------------------------------------
    # Recover key
    # --------------------------------------------------------

    private_key = (
        recover_private_key(
            M,
            a,
            t
        )
    )

    if private_key is None:
        private_key = (
            try_candidates(
                M,
                signatures
            )
        )

    if private_key is None:
        log.failure(
            "Private key tidak ditemukan."
        )

        log.warning(
            "Coba gunakan lebih banyak "
            "signature jika challenge mengizinkan."
        )

        io.close()

        return

    log.success(
        "[+] Private key ditemukan: "
        f"{private_key:#066x}"
    )

    # --------------------------------------------------------
    # Verify public key
    # --------------------------------------------------------

    assert verify_private_key(
        private_key
    )

    log.success(
        "[+] Public key verification OK"
    )

    # --------------------------------------------------------
    # SUBMIT
    # --------------------------------------------------------

    io.sendlineafter(
        b"TERMINAL> ",
        b"SUBMIT"
    )

    io.sendlineafter(
        b"ambassador_key_hex: ",
        f"{private_key:064x}".encode()
    )

    response = io.recvall(
        timeout=5
    )

    print(
        response.decode(
            errors="replace"
        )
    )


if __name__ == "__main__":
    main()
```

---

# 15. Catatan Implementasi `gmpy2.mpz`

Pada environment tertentu, library `ecdsa` dapat mengembalikan:

```python
gmpy2.mpz
```

untuk nilai besar seperti:

```python
curve.order
```

sedangkan `fpylll` mengharapkan Python `int`.

Karena itu, penting untuk melakukan:

```python
int(value)
```

sebelum memasukkan nilai ke lattice.

Contoh:

```python
N = int(curves.SECP256k1.order)
```

dan:

```python
M[i, j] = int(value)
```

Tanpa casting ini, error tipe seperti:

```text
TypeError
```

dapat muncul ketika membangun matrix.

---

# 16. Alternatif Menggunakan SageMath

Karena lattice adalah bagian terpenting challenge, SageMath juga sangat cocok.

Inti konstruksinya:

```python
N = Integer(curves.SECP256k1.order)
B = 2^240

M = Matrix(
    ZZ,
    dim,
    dim,
    M_rows
)

R = M.LLL()
```

Kemudian scan hasil:

```python
for row in R.rows():
    if abs(row[-1]) == N * B:
        d = abs(row[-2]) // B

        if d * G == Q:
            print(
                "private key:",
                hex(d)
            )
```

Pendekatan Sage biasanya lebih nyaman jika `fpylll` sulit dibangun di environment lokal.

---

# 17. Hasil Pengumpulan Signature

Dalam sesi exploit yang berhasil, 24 signature berhasil diperoleh.

Contoh output signature terakhir:

```text
[+] got sig 20/24:
r=63489919485424642861326260463835557048256571493037429840639501447704158662638
s=113555001744744019463503786660823236212193242359314146192057592718555692577820
h=36363478741588657833724702782371995344217651784474377902151761725959672448820

[+] got sig 21/24:
r=11778716002521472629139458015846356401080544032873829763775848483674435742421
s=103835075915342893477783805110500633876924859025810878399275892290956436746460
h=20861695320417475074030219609892481825823198551253101772575559552495526407713

[+] got sig 22/24:
r=43350848976809164559364146879360081731281826880326928293727918498109477242240
s=82679192240124148551858472235908463800328326406237892210100847833172402623926
h=106477647837424261717989832778511482768851140995559836900679938881156303370253

[+] got sig 23/24:
r=117658567566698007802769500?  # dipersingkat di sini
```

Yang penting bukan nilai masing-masing signature secara terpisah, tetapi constraint yang dibentuk oleh seluruh sample.

---

# 18. Hasil LLL

Setelah proses lattice reduction:

```text
[*] Menjalankan LLL / HNP lattice attack...
```

diperoleh private key:

```text
31c4e0e949921d9d86a7c56969fe7d553e7765708264225a2d1b1337aed5f24e
```

atau:

```text
0x31c4e0e949921d9d86a7c56969fe7d553e7765708264225a2d1b1337aed5f24e
```

Private key kemudian diverifikasi terhadap public key:

```text
d * G == Q
```

dan cocok.

---

# 19. Submit

Setelah key valid, kirim:

```text
SUBMIT
```

kemudian:

```text
ambassador_key_hex:
```

isi:

```text
31c4e0e949921d9d86a7c56969fe7d553e7765708264225a2d1b1337aed5f24e
```

Server memberikan:

```text
ACCESS GRANTED.
```

dan flag.

---

# 20. Output Verifikasi

Hasil solving yang berhasil:

```text
[+] got sig 24/24:
r=15395529285449022758782239634687791376474062481936791825088178680175627860122
s=23268901882017814590976980080183071630470704228150667545017663603252535523481
h=16187408321870607482773582212352868654592937225417133421406892388555292895426

[*] Menjalankan LLL / HNP lattice attack...

[+] Private key ditemukan:
0x31c4e0e949921d9d86a7c56969fe7d553e7765708264225a2d1b1337aed5f24e

[*] Verifying public key...
[+] Public key verification: OK

ACCESS GRANTED.
CYBERLEAGUE{3mb4ssy_c4bl3s_n0nc3_l34k_7d2f}
```

---

# 21. Root Cause

Kerentanan inti challenge adalah:

## Biased / Reduced-Entropy ECDSA Nonce

ECDSA memerlukan nonce acak yang tidak dapat diprediksi.

Challenge justru menggunakan:

```python
EFFECTIVE_BITS = 240
```

untuk sebuah kurva dengan order sekitar:

```text
256-bit
```

Akibatnya:

```text
k < 2^240
```

sehingga attacker mengetahui bahwa 16 MSB nonce selalu nol.

Informasi ini cukup untuk membangun instance:

```text
Hidden Number Problem
```

yang dapat diselesaikan menggunakan:

```text
Lattice Reduction / LLL
```

---

# 22. Kenapa Bukan Masalah pada ECDSA-nya?

ECDSA `secp256k1` sendiri tidak rusak.

Implementasi matematisnya tetap standar.

Masalahnya berada pada generator nonce:

```text
ECDSA
  │
  ├── private key aman
  ├── curve aman
  ├── signature formula aman
  │
  └── nonce k terlalu kecil
          │
          ▼
      HNP leakage
          │
          ▼
        LLL
          │
          ▼
     private key
```

Dengan nonce yang benar-benar uniform 256-bit, serangan ini tidak bekerja dengan cara yang sama.

---

# 23. Mengapa `RsaCtfTool` Tidak Relevan?

Walaupun tool seperti:

```text
RsaCtfTool
```

sangat berguna untuk challenge RSA, challenge ini menggunakan:

```text
ECDSA
```

bukan RSA.

Tool yang lebih relevan:

```text
SageMath
fpylll
ecdsa
pwntools
```

---

# 24. Kesalahan / Dead End yang Bisa Dihindari

### 24.1. Mencoba `ls` / `id`

Tidak ada shell.

Server hanya menyediakan:

```text
SIGN
SUBMIT
EXIT
```

### 24.2. Menebak private key

Private key adalah nilai 256-bit.

Brute force tidak realistis.

### 24.3. Menggunakan RSA tooling

Tidak relevan karena algoritmanya ECDSA.

### 24.4. Hanya mengumpulkan sedikit signature

Satu atau dua signature tidak cukup untuk lattice attack dengan parameter ini.

Gunakan sebanyak mungkin signature yang diizinkan.

Pada challenge ini:

```text
25 total operations
```

maka strategi optimal:

```text
24 SIGN
1 SUBMIT
```

---

# 25. Solve Chain

Secara ringkas:

```text
Connect
  │
  ▼
Dapatkan public key
  │
  ▼
Gunakan 24x SIGN
  │
  ▼
Kumpulkan (r, s, h)
  │
  ▼
ECDSA equation
  │
  ▼
k = a + td (mod n)
  │
  ▼
Nonce diketahui:
k < 2^240
  │
  ▼
Hidden Number Problem
  │
  ▼
Bangun lattice
  │
  ▼
LLL
  │
  ▼
Recover d
  │
  ▼
Verifikasi dG = Q
  │
  ▼
SUBMIT d
  │
  ▼
ACCESS GRANTED
  │
  ▼
FLAG
```

---

# 26. Ringkasan Teknik

| Komponen | Nilai |
|---|---|
| Algoritma | ECDSA |
| Curve | secp256k1 |
| Vulnerability | Biased nonce |
| Entropy nonce | 240 bit |
| Normalnya | 256 bit |
| Leakage | 16 MSB selalu `0` |
| Attack | Hidden Number Problem |
| Solver | Lattice Reduction / LLL |
| Signature digunakan | 24 |
| Total operasi | 25 |
| Operasi terakhir | `SUBMIT` |
| Tool | Python, pwntools, ecdsa, fpylll / Sage |

---

# 27. Flag

```text
CYBERLEAGUE{3mb4ssy_c4bl3s_n0nc3_l34k_7d2f}
```

---

## Referensi

Shared analysis:

```text
https://claude.ai/share/91e56aa3-59d4-4504-aa8f-775b95721cf4
```

> Writeup ini disusun dari hasil analisis dan verifikasi yang terdapat pada shared conversation tersebut. Bagian solver lattice dirapikan menjadi bentuk yang dapat dibaca dan dijalankan untuk tujuan reproduksi challenge.
