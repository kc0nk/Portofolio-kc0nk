---
ctf: "R3CTF 2026 (r3kapig)"
kategori: "Forensics"
challenge: "Tsuki's Rhythm Game"
flag: "r3ctf{f1n@1Iy-yOU_f1nD_tHE_S3CR3t_6EHiND_rHytHM-4Nd-Tr4c3_them0}"
teknik: "Rantai 5-tahap: beatmap AES-CBC → bytecode marshal tersembunyi di note type-99 → C2 dengan hh.exe sebagai dictionary → RDP bitmap cache → recovery phrase MetaMask"
---

# Tsuki's Rhythm Game — R3CTF 2026 (Forensics)

## Deskripsi Singkat

Rantai incident-response yang tersebar di folder game, packet capture, dan arsip evidence terproteksi password. Tujuan akhirnya adalah alamat wallet yang diturunkan dari recovery phrase MetaMask, tapi jalan ke sana melewati ekstraksi PyInstaller, decoding bytecode Python-marshal, protokol C2 custom yang memakai `hh.exe` sebagai dictionary encoding, dan rekonstruksi RDP bitmap-cache.

## Analisis

**Langkah 1 — Unpack game-nya dan dekripsi beatmap.** `TsukiRhythmGame.exe` di-pack PyInstaller. Ekstrak kode Python-nya dan baca chart loader-nya; beatmap-nya terenkripsi AES-CBC dengan key/IV hardcoded: `KEY = b"TsukiRhythmKey!!"`, `IV = b"TsukiRhythmIV!!!"`.

**Langkah 2 — Ekstrak bytecode marshal dari Eggdrasil.tsuki.** Mendekripsi lima chart-nya, `Eggdrasil.tsuki` menonjol: kebanyakan note-nya gameplay normal, tapi banyak yang memakai `type == 99`. Mod `advanced_stats.tsukimod` berisi kode yang mengumpulkan note type-99 tersebut, mengemas lane tiap note jadi 2 bit, dan memberikan byte hasil gabungan ke `marshal.loads`. Loader C2 tersembunyi ini mendownload dan menjalankan `Updater.exe` dari jaringan lokal. MD5 dari bytecode marshal-nya: `aed1e4e8b9061e19506848ca579e46ac`.

**Langkah 3 — Ekstrak Updater.exe dan reverse protokol C2-nya.** `tshark --export-objects http` memulihkan `Updater.exe` dari capture. Malware-nya terhubung ke `192.168.117.1:4444`. Pesan pertama client-ke-server *bukan* dot-encoded. Meng-XOR-nya dengan `13 37 c0 de` menghasilkan file PE yang valid — ini adalah `C:\Windows\hh.exe` (MD5 `2c8fe78d53c8ca27523a71dfd2938241`). Bukan eksfiltrasi tanpa alasan: encoder C2-nya membangun dictionary dari `hh.exe` (nilai byte → offset pertama byte itu muncul di `hh.exe`). Byte yang tidak ada di `hh.exe` dikirim sebagai escape integer negatif (`hh.exe` mengandung 248 dari 256 kemungkinan nilai byte; 8 sisanya muncul di traffic sebagai negatif).

**Langkah 4 — Decode pesan C2.** Setiap packet berikutnya adalah integer dipisah titik: split pada `.`, integer positif → lookup offset itu di dictionary hasil rekonstruksi, integer negatif → decode sebagai `abs(value)` (byte yang tidak ada di `hh.exe`), byte hasilnya = `kunci 16-byte || ciphertext AES-128-CBC || IV 16-byte`, dekripsi AES-128-CBC dengan padding PKCS#7. Command server yang ter-decode: `ipconfig /all`, `whoami`, `dir`, `tasklist`, menambahkan registry untuk enable RDP, membuat user `aurahack`, menambahkannya ke grup Administrators, mematikan firewall. Respons `whoami`: `desktop-gb98l3m\tsuki`.

Menjawab pertanyaan-pertanyaan itu di instance membuka password untuk `Evidence.zip`: `18ae3a54-1c1a-4f44-adca-9884acb80d9a`.

**Langkah 5 — Pulihkan recovery phrase MetaMask dari RDP bitmap cache.** `Evidence.zip` mengekstrak `Cache0000.bin`. File-nya diawali `RDP8bmp` — sebuah RDP bitmap cache, bukan database browser atau wallet. Pakai `bmc-tools` milik ANSSI untuk mengekstrak tile dan meng-collage-nya:

```bash
git clone https://github.com/ANSSI-FR/bmc-tools.git
python3 bmc-tools/bmc-tools.py -s Evidence_extracted -d rdp_tiles -b -v
```

2.943 tile direkonstruksi. Recovery phrase MetaMask yang terlihat: `labor trophy emerge material divorce input faint bench cricket merge sunset cream`.

**Langkah 6 — Turunkan akun Ethereum pertama.** MetaMask memakai `m/44'/60'/0'/0/0`. `cast wallet derive` milik Foundry:

```bash
cast wallet derive 'labor trophy emerge material divorce input faint bench cricket merge sunset cream' --accounts 1
# Address: 0x27A2481a2D840C64c1f6a99842E1A63A1586237e
```

## Eksploitasi / Solusi

Submit alamat wallet-nya; instance mengembalikan:

```
r3ctf{f1n@1Iy-yOU_f1nD_tHE_S3CR3t_6EHiND_rHytHM-4Nd-Tr4c3_them0}
```

## Catatan / Insight

Rantai forensik ini berhasil karena output setiap tahap persis input yang dibutuhkan tahap berikutnya: bytecode marshal-nya menyebutkan host+port C2; `hh.exe` adalah dictionary encoding yang membuat transcript C2 bisa di-decode; transcript-nya menjawab kuis instance yang membagikan password ZIP; ZIP-nya menyimpan RDP cache yang glyph-nya yang terlihat adalah seed phrase. Primitive RDP bitmap-cache adalah bagian paling baru dari toolkit ini, layak diinternalisasi karena ia mengubah rekaman apa pun dari sesi RDP attacker menjadi screen capture lewat `bmc-tools`.

## Flag

```
r3ctf{f1n@1Iy-yOU_f1nD_tHE_S3CR3t_6EHiND_rHytHM-4Nd-Tr4c3_them0}
```
