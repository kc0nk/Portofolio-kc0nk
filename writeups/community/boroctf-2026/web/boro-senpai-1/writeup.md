---
ctf: "boroCTF 2026"
kategori: "Web Exploitation"
challenge: "boro-senpai 1"
flag: "boroCTF{3l_psY_c0ngR00!}"
teknik: "IDOR di /profile/<username>; OSINT kanon mengidentifikasi handle Makise Kurisu, lalu route mengembalikan profilnya tanpa cek otorisasi"
sumber: "https://github.com/Abdelkad3r/boroCTF-2026"
---

# boro-senpai 1 — boroCTF 2026 (Web Exploitation)

## Deskripsi Singkat

Sebuah imageboard bertema Steins;Gate bernama `@channel`. Kamu mendarat sudah terautentikasi sebagai `hououin_kyouma` (identitas megalomaniak Okabe). Prompt soal memberi tujuan: temukan handle @channel lama milik asistennya — dan profilnya akan menjadi milikmu.

## Recon

Ada dua route yang bisa diakses: `/` (board, berisi thread dan post) dan `/profile/<username>`, di mana hanya `hououin_kyouma` yang di-link di UI. Halaman profil menampilkan pesan "Your profile is visible only to you." (Profilmu hanya terlihat olehmu). Ini hanyalah teks UI dari sebuah template, bukan pemeriksaan otorisasi sungguhan.

**Bagian OSINT.** Di thread "Does time travel violate conservation of energy?", seorang poster bernama `KuriGohanandKamehameha` memberi balasan fisika yang serius. Okabe merespons "I shall be observing them." Dia membalas ketus "I'm not your lab assistant. Don't @ me." Bahkan tanpa mengetahui kanon Steins;Gate, dialog ini sudah cukup menandai dia sebagai asisten Okabe, yaitu Makise Kurisu. Dengan pengetahuan kanon, `KuriGohanandKamehameha` adalah handle @channel kanoniknya.

## Analisis — Bug-nya Apa

IDOR (Insecure Direct Object Reference) di `/profile/<username>`. Handler route membaca username dari URL dan me-render profil user tersebut **tanpa membandingkannya dengan session yang sedang login**. String UI "Your profile is visible only to you" hanyalah template, bukan kontrol keamanan — otorisasi seharusnya terjadi di dalam handler.

## Eksploitasi / Solusi

Langsung akses profilnya:

```bash
curl -s https://<instance>.boroctf.com/profile/KuriGohanandKamehameha \
  | grep -oE 'boroCTF\{[^}]+\}'
# boroCTF{3l_psY_c0ngR00!}
```

Bio-nya membawa flag di field "personal note". "Visible only to you" hanyalah string template, bukan pemeriksaan server-side. Ini adalah contoh klasik dari Broken Object-Level Authorization, OWASP API Top-10 #1.

## Catatan / Insight

Flag adalah leetspeak dari **"El Psy Kongroo!"**, semboyan khas Okabe. Pelajaran untuk defender adalah pelajaran yang selalu diajarkan bug class ini: **jangan percaya begitu saja pada string UI, verifikasi sendiri**. Apa pun yang ada di dalam template bisa saja tidak sesuai dengan apa yang benar-benar diberlakukan oleh route handler. Handler harus membandingkan `<username>` dengan session yang aktif dan menolak akses kalau berbeda.

## Flag

```
boroCTF{3l_psY_c0ngR00!}
```
