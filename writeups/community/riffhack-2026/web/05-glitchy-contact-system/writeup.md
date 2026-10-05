---
ctf: "RIFFHACK 2026"
kategori: "Web"
challenge: "The Glitchy Contact System"
flag: "bitflag{d3bug_m0d3_1s_d4ng3r0us}"
teknik: "Prop RSC sudah ada di HTML sebelum client component-nya throw error dan menampilkan halaman kosong"
sumber: "https://github.com/Abdelkad3r/RIFFHACK/tree/main/05-web5-glitchy-contact-system"
---

# The Glitchy Contact System — RIFFHACK 2026 (Web)

## Deskripsi Singkat

Halaman `/contact` sengaja rusak: client component-nya throw Error saat mount yang pesannya mengandung flag, lalu mengembalikan `null`. `<main>`-nya ter-render kosong. Tapi prop yang sama sudah ada di HTML RSC *sebelum* throw-nya terjadi.

Ini juga challenge di mana penulis menghabiskan empat jam mengejar umpan. Pelajarannya ternyata persis itu.

## Analisis — Empat Umpan yang Dikejar

Marketplace-nya ditaburi string berbentuk-flag; setiap primitive web-app "sungguhan" yang dicoba memunculkan salah satunya:

1. `bitflag{w3bs0ck3t_upgr4d3_ssrf_2026}` — field Token IMDS via SSRF.
2. `bitflag{ssrf_1s_4_p4rty_cr4sh3r}` — env var `user-data` IMDS via SSRF (jawaban asli untuk The Trusting Verifier).
3. `bitflag{3xp0rts_sh0uld_n0t_b3_0p3n_b00ks}` — `SupportChatMessage.internalNote` via pivot SQLi (jawaban asli untuk The Night Dump).
4. `bitflag{jwt_5h4ll_n0t_p455}` — widget "Vendor Token" `/vendor` via forge `alg:none` dengan `isVendor:true`.

Setiap satu ini adalah bug sungguhan yang menjangkau nilai berbentuk-flag sungguhan. Tidak satu pun adalah jawaban untuk web5. Pola desain pembuat challenge — memakai ulang codebase yang sama lintas beberapa event, tiap brief menunjuk ke permukaan berbeda — berarti string yang sama berpindah antara umpan dan asli tergantung brief-nya.

## Eksploitasi / Solusi

Judulnya ("Glitchy Contact System") adalah seluruh jawabannya. `/contact` mengembalikan 200 dengan `<main>` kosong — itulah "glitch"-nya. Bundle client-nya (422 byte) mendestructure prop `flag`, throw Error yang mengandungnya saat mount, mengembalikan `null`. Tapi prop-nya sudah ada di payload RSC sebelum throw:

```bash
$ curl -s http://159.89.230.27/contact | grep -oE 'bitflag\{[^}]+\}'
bitflag{d3bug_m0d3_1s_d4ng3r0us}
```

Kelas bug yang sama dengan web4. Client component-nya tidak relevan; nilainya sudah dikirim di HTML.

## Catatan / Insight

Pembungkus debug-error ini layak direnungkan karena padanan produksinya terlihat identik: `console.error("User auth failed: token=${token}")`, `throw new Error("DB connect failed: ${connectionString}")`. Setiap error logger, crash reporter, dan console dev-tools browser menyimpan string berbentuk persis seperti ini. CTF ini mendramatisasinya; insiden dunia nyata terlihat sama.

## Flag

```
bitflag{d3bug_m0d3_1s_d4ng3r0us}
```
