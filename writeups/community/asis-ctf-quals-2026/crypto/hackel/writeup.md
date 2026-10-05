---
ctf: "ASIS CTF Quals 2026"
kategori: "Crypto"
challenge: "Hackel"
flag: "ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}"
teknik: "Kata ciphertext dicetak sebagai string mentah (bit=1 jika mengandung 'b'); verifier equivalent-key tidak pernah menyentuh conjugator rahasia, cukup diisi embedding diagonal 10-cycle + 11-cycle"
---

# Hackel — ASIS CTF Quals 2026 (Crypto, Baby)

## Deskripsi Singkat

Handout-nya satu file Python, `hackel.py`. Servis mengekspos lima aksi menu lewat TCP; `[4]` (Submit Recovered Equivalent Key) dan `[5]` (Interactive Speed Challenge) keduanya mencetak flag saat berhasil. Keyspace yang diiklankan `(11!)² = 1.593.350.922.240.000` adalah dua pilihan conjugator independen yang dipakai membangun alfabet huruf besar dan kecil.

## Analisis — Skemanya

Permutasi beraksi pada `n = 11` titik dan compose kiri-ke-kanan. Setiap alfabet dibangkitkan dari conjugator acak: `a` (10-cycle, order 10) dan `b` (11-cycle, order 11) independen; `c`, `d`, `e` diturunkan darinya. Bit flag di-encode sebagai **kata di atas alfabet huruf kecil**: bit `0` adalah `a^k` (`k ≥ 1`); bit `1` adalah `a^k b`.

**Celah 1 — ciphertext-nya tidak pernah dienkripsi.** Menu opsi `[2]` mencetak kata-kata itu **sebagai string**, bukan sebagai permutasi yang sudah dievaluasi. Kedua cabangnya berbeda satu karakter yang terlihat, jadi **bit = 1 jika dan hanya jika kata itu mengandung `b`**. 496 kata = 496 bit = 62 byte = panjang flag:

```python
bits = "".join("1" if "b" in w else "0" for w in words)
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).decode()
```

Bahkan kalau server mengevaluasi kata-katanya jadi permutasi, bit-nya tetap ditentukan oleh **koset `<a>`**: `a^k` berada di `<a>` (bit 0), dan `a^k·b` tidak, karena `|b| = 11` tidak membagi `|<a>| = 10`. Keanggotaan koset tidak bergantung basis dan tidak butuh kunci.

**Celah 2 — verifier tidak pernah menyentuh rahasianya.** Menu `[4]` (`submit_key`) adalah jalur yang dimaksud, tapi hanya memvalidasi submission terhadap presentasi **publik** — setiap pengecekan ada pada permutasi yang disubmit, tidak satu pun pada rahasia server. Substitusi `C = AB`, `D = A⁻¹BAB`, `E = CD` meruntuhkan delapan dari sepuluh relasi atas jadi tautologi, menyisakan `<A, B | A^10 = 1, B^11 = 1>`. Relasi campuran dipenuhi dengan menetapkan `lower := upper`. Bahkan grup Frobenius `AGL(1, 11)` order 110 lolos setiap gerbang — 362.880× lebih kecil dari `S_11`.

**Celah 3 — speed challenge.** Menu `[5]` membangkitkan 16 kata segar dengan encoding sama dan menuntut klasifikasi dalam 5 detik. Tes `"b" in word` yang sama menjawabnya seketika.

## Eksploitasi / Solusi

```python
A = tuple((i + 1) % 10 if i < 10 else 10 for i in range(11))  # 10-cycle fixing 10
B = tuple((i + 1) % 11 for i in range(11))                    # 11-cycle
```

`submit_key` lalu mencetak flag.

## Catatan / Insight

**Encoding bukan enkripsi.** Kata-katanya tidak pernah dievaluasi jadi grup permutasi; grupnya cuma dekorasi di sekitar kanal plaintext. Dan **verifier yang tidak pernah menyentuh rahasia tidak sedang memverifikasi kunci** — `submit_key` menerima representasi apa pun yang memenuhi persamaan yang dipublikasikan, jadi key recovery runtuh jadi "selesaikan persamaan yang dipublikasikan", yang delapan relasinya hilang dengan aljabar dan dua lagi dengan satu pasang cycle 10-plus-11.

## Flag

```
ASIS{sEm1d!r3c7_gr0uP_pr3S3nt4T10n____k3y___r3C0verY_4TtacK!!}
```
