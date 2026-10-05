---
ctf: "Anti-Slop CTF 2026"
kategori: "OSINT"
challenge: "Geoguessr"
flag: "slopped{h0w_d0_agent5_sl0p_nmpz?}"
teknik: "Client-side crypto mengubah tebakan lokasi jadi H3 resolution-8 cell → kunci Argon2id → dekripsi Shamir share; kumpulkan 9 dari 10 share untuk rekonstruksi kunci AES master"
---

# Geoguessr — Anti-Slop CTF 2026 (OSINT, 487 poin)

## Deskripsi Singkat

Sepuluh panorama gaya Geoguessr NMPZ (No Move, No Pan, No Zoom). Permukaannya terlihat seperti puzzle pencarian visual murni, tapi win condition sebenarnya adalah memulihkan kunci per-lokasi yang bisa diverifikasi, yang dibuat komputabel oleh client tanpa pernah memuat Google Street View sungguhan.

## Analisis

Web client-nya **tidak menilai tebakanmu secara visual**. Ia mengonversi tebakanmu jadi **H3 resolution-8 cell** (grid heksagonal hierarkis milik Uber, ~700 m per sisi), menurunkan kunci Argon2id dari cell tersebut plus nama challenge, meng-hash kuncinya, dan membandingkannya dengan target hash yang dipublikasikan. Kalau hash-nya cocok, kunci yang sama mendekripsi satu Shamir share terenkripsi AES-CBC. Kumpulkan 9 dari 10 share dan rekonstruksi GF(256) menghasilkan kunci AES master untuk flag.

**Kenapa H3 resolution 8 spesifik?** Cell resolusi 8 berukuran ~700 m — cukup toleran sehingga koordinat dalam radius ~350 m dari lokasi sebenarnya jatuh di cell yang benar, tapi cukup ketat sehingga "negara benar, kota salah" tidak lolos. Ini titik manis untuk pencarian OSINT yang bisa diverifikasi: OSINT player manusia bisa triangulasi sampai ~350 m memakai anchor visual, sementara pipeline pengenalan-gambar berbasis LLM yang percaya diri menebak pusat kota biasanya meleset satu cell.

**Kenapa threshold-nya 9 dari 10 share?** Shamir's Secret Sharing memungkinkan threshold di-tune di bawah total jumlah share. Threshold 9-dari-10 berarti satu panorama boleh dilewati (pilih yang paling sulit). Client mengimplementasikan threshold ini di kode rekonstruksi GF(256) yang tertanam, jadi solver bisa mengonfirmasi kombinasi 9-share mana pun berhasil sebelum submit.

## Eksploitasi / Solusi

Kesulitan OSINT-nya runtuh dari "tebak koordinat persis" jadi "mendarat di H3 cell yang benar." Identifikasi cell yang benar untuk minimal 9 dari 10 lokasi, turunkan kunci Argon2id masing-masing, dekripsi share-nya, rekonstruksi kunci AES master:

```
slopped{h0w_d0_agent5_sl0p_nmpz?}
```

## Catatan / Insight

"NMPZ" adalah ruleset Geoguessr yang melucuti tool navigasi panorama dan memaksa identifikasi lokasi dari satu sudut pandang statis. Lelucon di flag-nya — "how do agents slop NMPZ?" — adalah kedipan mata dari pembuat challenge: agent berbasis LLM terkenal buruk di NMPZ karena mereka berhalusinasi lokasi dari bukti visual yang lemah dan tidak punya kesabaran untuk triangulasi seperti OSINT player manusia.

**Pelajaran lebih luas:** crypto sisi-client bisa meruntuhkan masalah pencarian OSINT jadi loop iterasi yang bisa diverifikasi, yang menguntungkan triangulasi manusia dibanding halusinasi agent. Baca kode client yang dikirim servis, bukan cuma menebak-nebak gambar.

## Flag

```
slopped{h0w_d0_agent5_sl0p_nmpz?}
```
