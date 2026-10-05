---
ctf: "NoHackNoCTF 2026 (NHNC)"
kategori: "Crypto"
challenge: "modern-crypto-101"
flag: "NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}"
teknik: "Reuse keystream AES-CTR karena nonce konstan; rekonstruksi plaintext guest untuk memulihkan keystream, lalu decode ciphertext admin"
sumber: "https://github.com/Abdelkad3r/NoHackNoCTF-2026/tree/main/crypto/modern-crypto-101"
---

# modern-crypto-101 — NoHackNoCTF 2026 (Crypto)

## Deskripsi Singkat

AES-CTR dengan nonce konstan, dienkripsi lima kali: empat "guest ticket" JSON yang isi plaintext-nya berasal dari handout publik, dan satu "admin ticket" yang mengandung flag. Reuse keystream yang sama berarti satu plaintext yang diketahui bisa mengupas seluruh keystream dan setiap ciphertext lainnya ikut terbuka.

## Analisis

**Langkah 1 — Konfirmasi nonce-nya konstan.** `chall.py`:

```python
KEY   = get_random_bytes(16)
NONCE = b"ticket42"
FLAG  = "NHNC{REDACTED}"

def encrypt(ticket):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(ticket).hex()
```

Setiap panggilan membaca kunci 16-byte yang sama, nonce 8-byte yang sama, dan membiarkan `pycryptodome` men-default counter awal ke nol. Jadi setiap ciphertext di-XOR terhadap keystream `K` yang sama.

**Langkah 2 — Lihat reuse-nya dengan mata telanjang.** Setiap plaintext diawali `{"event":"modern-crypto-101","role":"` sebelum bercabang jadi `guest` atau `admin`. Sejajarkan 51 byte pertama (102 karakter hex) dari setiap ciphertext:

```
guest_0 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
guest_1 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
guest_2 = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 c0890bc6b f92f2a5dd1b971c73dd0
admin   = c3c8593c1adc1add7df8c32c549f785f67d6d3a86d486c4fa22322fe0c9848cfa7e66ae8bf2 a1998a671 f92f2a5dd1b971c73dd0
                                                                                     ↑ 5 byte berbeda
```

Keempat guest identik byte-demi-byte selama 37 byte, menyimpang persis 5 byte di batas `guest`/`admin`, lalu sejajar lagi di `","name":"`. `admin[37:42] XOR guest[37:42] = b"guest" XOR b"admin" = 06 11 08 1a 1a`. Keystream yang sama, terkonfirmasi sebelum ada kode dekripsi apa pun ditulis.

**Langkah 3 — Rekonstruksi plaintext guest 2.** Guest 2 punya ciphertext terpanjang (171 byte) dan lebih dari cukup untuk menutupi 160 byte milik admin_cipher. Template JSON-nya tetap; `name` dan `seat` berasal dari `public.txt`:

```python
def make_guest(name, seat):
    return json.dumps({
        "event": "modern-crypto-101",
        "role":  "guest",
        "name":  name,
        "seat":  seat,
        "note":  "enjoy the workshop",
    }, separators=(",", ":")).encode()

pt2 = make_guest(
    "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
    "N-0705",
)
```

`separators=(",", ":")` dan pelestarian urutan dict di Python 3.7+ membuat ini byte-identik dengan yang dihasilkan `chall.py`.

## Eksploitasi / Solusi

```python
ct2 = bytes.fromhex(guest_cipher_2)
assert len(pt2) == len(ct2)
keystream = bytes(p ^ c for p, c in zip(pt2, ct2))

admin_ct  = bytes.fromhex(admin_cipher)
admin_pt  = bytes(a ^ k for a, k in zip(admin_ct, keystream))
print(admin_pt.decode())
```

```json
{"event":"modern-crypto-101","role":"admin","name":"organizer","seat":"ROOT",
 "note":"priority access granted","flag":"NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}"}
```

## Catatan / Insight

Isi flag-nya mengeja perbaikannya sendiri: "CTR keystreams should never return" (keystream CTR tidak boleh pernah kembali/berulang). Keunikan nonce adalah seluruh aturannya; implementasi apa pun yang berbagi `(key, nonce, counter)` antara dua enkripsi telah meruntuhkan AES-CTR menjadi one-time pad dengan pad yang dipakai ulang — mode kegagalan terburuk untuk stream cipher.

## Flag

```
NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}
```
