---
ctf: "DalCTF 2026"
kategori: "Crypto"
challenge: "LCG Seed Squared"
flag: "DalCTF{533m1ng1y_r4nd0m1y_g3n3r473d_num63rs}"
teknik: "Known-plaintext atas output multiplikatif t_i = ord(flag[i]) * x_i; flag[0]='D'=68 langsung memberi x_1 tanpa inversi LCG"
---

# LCG Seed Squared — DalCTF 2026 (Crypto)

## Deskripsi Singkat

Script-nya:

```python
def rng(y):
    return pow(int((175*y + 17) / 14 + 45), 15, 4294967295)

# x_0 = sum(ord(c) for c in seed)  # string seed tidak diketahui
for i in range(len(flag)):
    x = rng(x)
    print(ord(flag[i]) * x)
```

Jadi output `t_i = ord(flag[i]) * x_{i+1}`, di mana `x_{i+1} = rng(x_i)` dan `x_0` adalah state awal turunan seed.

## Analisis

Bingkai "Seed Squared" pada nama challenge mengarahkanmu menyerang seed-nya (mengkuadratkan, memfaktorkan, merekonstruksi jumlah awal dari state LCG). **Jangan.** Format flag-nya sudah diketahui: `DalCTF{…`, jadi `flag[0] = 'D'` dan `ord('D') = 68`.

```
t_0 = 71303168 = 68 * 1048576
```

sehingga `x_1 = 1048576` langsung keluar. Tanpa pemulihan seed, tanpa inversi LCG — cukup satu byte known-plaintext.

## Eksploitasi / Solusi

```python
import re

with open("output (9).txt") as f:
    ts = [int(x) for x in re.findall(r"\d+", f.read())]

def rng(y):
    return pow(int((175*y + 17) / 14 + 45), 15, 4294967295)

x = ts[0] // ord('D')      # x_1
flag = ['D']
for t in ts[1:]:
    x = rng(x)
    assert t % x == 0
    flag.append(chr(t // x))

print(''.join(flag))
```

Setiap pembagian jatuh bersih ke ASCII yang bisa dicetak.

## Catatan / Insight

**Pelajaran untuk defender:** stream cipher apa pun yang outputnya `f(plaintext) * internal_state` rusak begitu satu byte plaintext diketahui. Prefix format flag hampir selalu diketahui di CTF; di produksi, magic number format file, envelope pesan, dan framing protokol memainkan peran yang sama.

**Kelas bug:** serangan known-plaintext lewat output multiplikatif; prefix-format-flag sebagai known prefix.

## Flag

```
DalCTF{533m1ng1y_r4nd0m1y_g3n3r473d_num63rs}
```
