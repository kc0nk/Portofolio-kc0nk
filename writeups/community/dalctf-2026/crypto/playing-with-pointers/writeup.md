---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "Playing with Pointers"
flag: "DalCTF{s0m3_fUn_w17h_P01n73r5}"
teknik: "Type punning gaya Quake: cast float* ke long* menghasilkan pola bit IEEE-754 dari (float)(c)^2; balik dengan unpack float, sqrt, round"
---

# Playing with Pointers — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Source C-nya:

```c
for (int i = 0; i < N; i++) {
    fflag[i]  = (float)FLAG[i];
    fflag[i] *= fflag[i];           // kuadratkan float-nya
    // TODO: salin fflag[i] ke lflag[i] — tapi aku lagi main Quake
    printf("%ld\n", lflag[i]);
}
```

Baris "salin"-nya *hilang* dan komentarnya menyebut Quake. Trik terkenal Quake III adalah **fast inverse square root**, yang bekerja dengan menginterpretasi ulang pola bit float sebagai integer:

```c
i = *(long *)&y;        // type-pun float → int
```

## Analisis

Jadi baris yang hilang adalah:

```c
lflag[i] = *(long *)&fflag[i];
```

Setiap `long` yang dicetak adalah **pola bit IEEE-754** dari `(float)(char)²`.

## Eksploitasi / Solusi — Membalik

Untuk tiap nilai output:

1. Kemas sebagai 4 byte little-endian.
2. Buka kemasan sebagai float (`<f`).
3. Ambil `sqrt`, bulatkan, `chr`.

```python
import struct, math

vals = [int(x) for x in open("output (11).txt").read().split()]
flag = ''
for v in vals:
    f = struct.unpack('<f', struct.pack('<I', v & 0xFFFFFFFF))[0]
    flag += chr(round(math.sqrt(f)))
print(flag)
```

→ `DalCTF{s0m3_fUn_w17h_P01n73r5}`

## Catatan / Insight

**Frasa diagnostiknya:** `*(long *)&float` (atau `*(int *)&float`, `*(uint32_t *)&float`). Begitu source C meng-cast pointer float ke pointer integer (atau sebaliknya), integer yang kamu baca adalah pola bit IEEE-754, bukan konversi numerik. Pola ini adalah menu tetap crypto CTF sekaligus anti-pattern undefined-behavior di dunia nyata — C membakukan type punning lewat `union` atau `memcpy`, tidak pernah lewat pointer cast.

**Kelas bug:** kebocoran pola bit IEEE-754; type punning lewat pointer cast undefined-behavior.

## Flag

```
DalCTF{s0m3_fUn_w17h_P01n73r5}
```
