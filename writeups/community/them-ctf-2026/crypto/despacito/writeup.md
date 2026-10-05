---
ctf: "THEM?! CTF 2026"
kategori: "Crypto"
challenge: "Despacito"
flag: "THEM?!CTF{D3S_4774K_W3S_AW3S0M3}"
teknik: "Kunci lemah DES yang disamarkan lewat parity bit (E1E1E1E1F0F0F0F0 ↔ E0E0E0E0F1F1F1F1); encrypt == decrypt"
sumber: "https://github.com/Abdelkad3r/themectf-2026"
---

# Despacito — THEM?! CTF 2026 (Crypto)

## Deskripsi Singkat

`ques.py` menjalankan DES-ECB dengan kunci `E1E1E1E1F0F0F0F0`, mem-padding dengan `*` hingga kelipatan 8, lalu meng-encode hasilnya dengan base64.

## Analisis

DES punya tepat empat **kunci lemah (weak key)** di mana enkripsi sama dengan dekripsi (`E_k(E_k(P)) == P`):

```text
01 01 01 01 01 01 01 01
FE FE FE FE FE FE FE FE
1F 1F 1F 1F 0E 0E 0E 0E
E0 E0 E0 E0 F1 F1 F1 F1   ← ini
```

Bandingkan kunci yang diberikan dengan weak key ketiga, byte demi byte:

```text
E1 vs E0  →  berbeda di bit 0 (LSB)
F0 vs F1  →  berbeda di bit 0 (LSB)
```

Setiap LSB byte adalah **bit parity**. Permuted Choice 1 milik DES hanya menyimpan 56 bit teratas dari kunci 64-bit, jadi `E1E1E1E1F0F0F0F0` dijadwalkan menjadi *persis kunci 56-bit yang sama* dengan weak key `E0E0E0E0F1F1F1F1`. Kunci yang diberikan adalah weak key yang disamarkan lewat bit parity.

Dengan weak key, enkripsi sama dengan dekripsi. Memanggil `cipher.decrypt` (atau `cipher.encrypt` — sama saja di sini) pada ciphertext hasil decode base64 langsung menghasilkan plaintext-nya.

## Eksploitasi / Solusi

```bash
$ ./solve.py
[+] key e1e1e1e1f0f0f0f0 -> weak after parity-strip? True
[+] decrypt == encrypt (weak-key cross-check passes)
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

## Catatan / Insight

**Pelajaran untuk defender:** empat weak key DES diajarkan di setiap kelas kriptografi pengantar dan masih muncul di kode produksi tahun 2026, biasanya disamarkan di balik kembarannya lewat bit parity. Kalau kamu mengaudit sistem yang masih memakai DES sama sekali (seharusnya tidak), cek key derivation-nya untuk delapan kembaran bit-parity dari setiap weak key, jangan cuma bentuk kanoniknya.

## Flag

```
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```
