---
ctf: "BhAcKAri CTF 2026"
kategori: "Misc"
challenge: "Cake (Minecraft datapack)"
flag: "bhackariCTF{_c4n_i_h4v3_4_sl1c3_}"
teknik: "Vigenère aditif 63-simbol dikunci empat integer UUID player; twist floor-mod (semantik Python, bukan truncated-mod Java)"
---

# Cake (Minecraft datapack) — BhAcKAri CTF 2026 (Misc)

## Deskripsi Singkat

> *"My friend told me he made the world's most delicious cake, but he protected it with a password!"*

Handout-nya adalah world save **Minecraft Java Edition 1.21.10**. Boot di mode adventure menempatkanmu di depan landasan (anvil) dan peti berisi selembar kertas. Datapack `ctf` menolak setiap input kertas-rename kecuali cocok dengan password 20-karakter dari `[a-zA-Z0-9_]`. Flag-nya `bhackariCTF{<password itu>}`.

**Kamu tidak perlu menjalankan game.** Seluruh validator adalah tumpukan file `.mcfunction` plus NBT player — bisa dibaca sebagai teks/biner langsung dari disk, bisa dibalik dengan tangan.

## Analisis — Cipher-nya

`for.mcfunction`, dipangkas ke satu iterasi:

```text
# ambil satu karakter input dan cari index alfabetnya
function ctf:gc   with storage ctf:data ctf.conv   # tmp := in[tmpi:tmpi2]
function ctf:gidx with storage ctf:data ctf.conv   # idx := idx[tmp]

# uidx = i % 4
scoreboard players operation $c tmpi %= $c const1  # const1 = 4

# baca UUID[uidx] dari NBT player
function ctf:gk with storage ctf:data ctf.conv     # k := @p.UUID[uidx]

# enc[i] = (idx + k) mod 63
scoreboard players operation $c k %= $c const2     # const2 = 63
scoreboard players operation $c idx += $c k
scoreboard players operation $c idx %= $c const2
function ctf:ak with storage ctf:data ctf.conv     # enc.append(idx)
```

"Alfabet"-nya adalah urutan key di `idx.mcfunction`: `a → 0, b → 1, …, z → 25, A → 26, …, Z → 51, 0 → 52, …, 9 → 61, _ → 62`. Jadi cipher-nya adalah **Vigenère aditif 63-simbol** yang dikunci empat integer UUID player.

**Twist floor-mod.** Kehalusan krusial: `%=` di aritmetika scoreboard Minecraft adalah **floor-mod (semantik Python), bukan `%` truncated milik Java.** Memakai `%` Java menghasilkan nilai antara negatif yang tidak cocok dengan target positif mana pun di `prechk`, membuat posisi 1..N terlihat tidak terpecahkan. Beralih ke floor-mod menyelesaikan setiap posisi dengan bersih.

**Ciphertext target.** `prechk.mcfunction` adalah dua puluh pengulangan pola akumulator: `tmp` dimulai di 29, delta ±N per posisi. Urutan target hasil ekstraksi:

```text
[29, 7, 29, 47, 29, 13, 35, 41, 23, 26, 28, 33, 23, 4, 54, 45, 20, 7, 28, 33]
```

## Eksploitasi / Solusi

Parse `playerdata/72c97782-…-d1ed.dat` dengan `nbtlib`:

```python
UUID = [1925805954, -557366980, -1859783841, -1036135955]
```

Balik tiap posisi:

```python
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
expected = [29, 7, 29, 47, 29, 13, 35, 41, 23, 26, 28, 33, 23, 4, 54, 45, 20, 7, 28, 33]
flag = "".join(alphabet[(enc - UUID[i % 4]) % 63] for i, enc in enumerate(expected))
# _c4n_i_h4v3_4_sl1c3_
```

## Catatan / Insight

**Pelajaran untuk defender:** **datapack Minecraft adalah source code sungguhan.** `.mcfunction` apa pun yang bisa kamu baca adalah `.mcfunction` yang bisa dibaca attacker. "Puzzle" challenge ini adalah jebakan floor-mod — Minecraft memakai semantik `%` gaya Python, yang berbeda dari `%` truncated milik Java. Kalau kamu mengimplementasikan cipher-nya di Java, kamu akan melihat residu negatif; kalau di Python, langsung berfungsi. Defender yang mengirimkan konten gaya game-mod harus memperlakukan isi datapack sebagai sepenuhnya publik.

## Flag

```
bhackariCTF{_c4n_i_h4v3_4_sl1c3_}
```
