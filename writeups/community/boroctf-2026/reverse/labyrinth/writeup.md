---
ctf: "boroCTF 2026"
kategori: "Reverse Engineering"
challenge: "labyrinth"
flag: "boroCTF{es4@pe_wA5_1nev!table}"
teknik: "Maze acak yang fungsi hope()-nya menjalankan marshal.loads atas hasil LCG-XOR(sequence, mod); brute-force 10.000 nilai mod dengan pre-filter di marker 0xE3"
---

# labyrinth — boroCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Sebuah script Python berukuran 5 KB. Kamu muncul di posisi `(50, 50)` pada grid 100×100 dan mencoba kabur dari seekor Minotaur. Setiap giliran, labirin membangkitkan ulang dinding secara acak, kamu memilih arah `N`/`S`/`E`/`W`, dan fungsi `hope()` dipanggil. Setelah 100 giliran, script mencetak:

```
The bull finds you. It is not a painless death.
```

Labirin ini **tidak mungkin dimenangkan** dengan bermain langsung. Seluruh inti soal ini adalah analisis statis terhadap fungsi `hope()`.

## Analisis — Membaca `hope()`

```python
def hope():
    try:
        mod = (player_pos[0] ^ (player_pos[1] + player_pos[1])) * player_pos[0]
        decrypted = rsa_encrypt(sequence, mod)         # nama fungsi menyesatkan
        code      = marshal.loads(decrypted)
        impossible = types.FunctionType(code, globals(), "impossible")
        impossible()
    except Exception:
        pass
```

Tiga hal penting di sini:

1. `rsa_encrypt` adalah nama yang menyesatkan. Implementasi sebenarnya adalah stream cipher XOR yang keystream-nya berasal dari LCG (Linear Congruential Generator) bergaya glibc, di-seed oleh nilai `mod`. Konstanta `1103515245` dan `12345` adalah bukti kuatnya: itu adalah LCG klasik dari Numerical Recipes / `rand()` glibc.
2. Byte hasil dekripsi diberikan ke `marshal.loads`. Kalau kebetulan valid sebagai code object Python, `FunctionType` akan membungkusnya dan `impossible()` memanggilnya. Ini adalah "arbitrary-code-execution-sebagai-puzzle".
3. `except Exception: pass` adalah satu-satunya jaring pengaman. Setiap nilai `mod` yang salah akan melempar exception dan kegagalannya ditelan begitu saja tanpa jejak.

Jadi soal ini tereduksi menjadi: temukan pasangan unik `(r, c)` di mana `mod = (r ^ (c+c)) * r` mendekripsi `sequence` 512-byte tertanam menjadi code object marshal yang valid.

## Eksploitasi / Solusi

**Brute-force, tapi dengan pre-filter.** Brute force naif atas 10.000 sel lambat karena `marshal.loads` pada data acak bisa mengalokasikan memori raksasa (gigabyte) kalau byte pertama kebetulan terbaca sebagai header `TYPE_LONG` / `TYPE_TUPLE` / `TYPE_DICT` yang sangat besar. Solusinya: pre-filter di byte marker `0xE3` (yaitu `TYPE_CODE | FLAG_REF`, marker code-object level-teratas di Python modern) untuk mempersempit 10.000 sel menjadi sekitar 17 sel saja:

```python
import marshal

LCG_A, LCG_C = 1103515245, 12345

def stream_decrypt(data, seed):
    state = seed & 0xFFFFFFFF
    out = bytearray()
    for b in data:
        state = (LCG_A * state + LCG_C) & 0xFFFFFFFF
        out.append(b ^ ((state >> 16) & 0xFF))
    return bytes(out)

for r in range(100):
    for c in range(100):
        mod = (r ^ (c + c)) * r
        decrypted = stream_decrypt(sequence, mod)
        if decrypted[:1] != b'\xe3':
            continue
        try:
            code = marshal.loads(decrypted)
        except Exception:
            continue
        print(r, c, mod, code.co_consts)
```

Satu sel berhasil terdekripsi menjadi code object yang bersih: `(91, 68)`, dengan `mod = (91 ^ 136) * 91 = 19201`. Tuple `co_consts`-nya adalah:

```python
(None, 'Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9', 1, 2, 3)
```

Decode base64 dari string konstantanya:

```python
base64.b64decode('Ym9yb0NURntlczRAcGVfd0E1XzFuZXYhdGFibGV9').decode()
# boroCTF{es4@pe_wA5_1nev!table}
```

## Catatan / Insight

"Escape was inevitable" (kabur adalah hal yang tak terelakkan) — karena labirin ini memang tidak pernah bisa dimenangkan lewat gameplay; satu-satunya "jalan keluar" adalah yang akan ditemukan oleh penganalisis statis, bukan oleh pemain yang benar-benar mencoba lari dari Minotaur.

**Kenapa pre-filter di `0xE3` penting?** `marshal.loads` atas data acak bisa mengalokasikan gigabyte memori ketika byte pertama kebetulan terbaca sebagai header raksasa. `0xE3` adalah `TYPE_CODE | FLAG_REF`, penanda code-object level-teratas. Pre-filter ini mempersempit ruang kandidat dari 10.000 menjadi sekitar 17, tanpa pernah memanggil `marshal.loads` pada kandidat yang berpotensi meledak (memory bomb).

## Flag

```
boroCTF{es4@pe_wA5_1nev!table}
```
