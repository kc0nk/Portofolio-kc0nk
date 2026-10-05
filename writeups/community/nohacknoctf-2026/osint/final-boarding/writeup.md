---
ctf: "NoHackNoCTF 2026 (NHNC)"
kategori: "Misc / OSINT"
challenge: "Final Boarding"
flag: "NHNC{20260505_GK55}"
teknik: "Foto boarding gate tunggal; EXIF + registrasi pesawat + identifikasi bandara lewat 4 sinyal independen + lookup jadwal penerbangan"
---

# Final Boarding — NoHackNoCTF 2026 (Misc / OSINT)

## Deskripsi Singkat

Satu foto boarding gate. Prompt-nya meminta `NHNC{YYYYMMDD_FLIGHT}`: tanggal foto diambil dan nomor penerbangan IATA yang akan dinaiki si pemotret. Empat sinyal independen di dalam file konvergen ke tepat satu penerbangan.

## Analisis

**Langkah 1 — EXIF untuk tanggal.**

```
$ exiftool Final_boarding.png | grep -iE 'date|offset|make|model|gps'
DateTimeOriginal      : 2026:05:05 14:49:53
OffsetTimeOriginal    : +09:00
Model                 : Pixel 8
GPSImgDirection       : 134/1 (Magnetic)
```

Tanggal terkunci ke 2026-05-05 JST: Children's Day Golden Week, hari libur berturut-turut terakhir. Field lat/lon sudah dihapus, tapi `GPSImgDirection` bertahan: 134° magnetik. Deklinasi magnetik Kansai sekitar −7°, memberi bearing sejati mendekati 127° (tenggara).

**Langkah 2 — Baca registrasi pesawat.** Crop bagian ekor fuselage:

```python
img = Image.open("Final_boarding.png")
w, h = img.size
img.crop((int(w*0.2), int(h*0.32), int(w*0.95), int(h*0.55))).save("tail.png")
```

Di antara "star" dan mesin: `JA06JJ`. Itu pola registrasi Jetstar Japan (JJP / GK); blok `JA0xJJ` dialokasikan untuk armada A320. Cross-check terhadap database airframe mengonfirmasi ini adalah Jetstar Japan Airbus A320-232(WL).

**Langkah 3 — Identifikasi bandara dari empat sinyal.** Empat petunjuk bertumpuk dalam satu frame:

1. **Ground service equipment.** Truk putih dengan wordmark biru besar `ANA`: ramp yang ditangani ANA.
2. **Branding jet-bridge.** Panel `SMBC` di jembatan: Sumitomo Mitsui, ciri khas familiar di KIX Terminal 1.
3. **Ekor pesawat tetangga.** Ekor kuning dengan lengkung phoenix merah: livery Hainan Airlines. Tujuan Hainan di Jepang tahun 2026 adalah KIX, NRT, NGO — menyingkirkan Fukuoka, New Chitose, Naha, dan sebagian besar basis regional Jetstar Japan.
4. **Latar pemandangan.** Viaduk horizontal panjang di depan siluet gunung: Sky Gate Bridge R (3.75 km) menuju Rinku Town dengan latar pegunungan Izumi. Arah 134° magnetik dari EXIF adalah busur tenggara, persis di mana penumpang di gate T1 pier akan melihat pemandangan itu.

Satu bandara memenuhi keempatnya: Kansai International Airport (KIX / RJBB), Terminal 1.

**Langkah 4 — Lookup jadwal penerbangan.** Halaman pencarian penerbangan resmi Kansai untuk keberangkatan Jetstar Japan di hari itu:

```
GET https://www.kansai-airport.or.jp/en/flight/kix_searchresult
        ?KUBUN=DD&submit=1&AIRLINE=GK

15:15  TAIPEI  GK55 / Jetstar Japan   Terminal T1 - C
23:25  TAIPEI  GK57 / Jetstar Japan   Terminal T1 - C
```

Dua keberangkatan GK. Timestamp EXIF 14:49 menempatkan si pemotret 26 menit sebelum push-back GK55 pukul 15:15: tepat di final boarding. GK57 delapan jam kemudian dan tersingkir hanya dari waktu saja.

Cross-check di FlightAware: `JJP55 06:30 UTC → 15:30 JST daily, RJBB → RCTP`. Rotasi harian A320 Kansai-ke-Taipei.

## Eksploitasi / Solusi

Flag: `NHNC{20260505_GK55}` (IATA `GK55`, bukan callsign ATC `JJP55`; prompt-nya eksplisit soal itu).

## Catatan / Insight

**Kenapa dibutuhkan empat sinyal independen untuk mengidentifikasi bandaranya?** Satu sinyal saja ambigu. Sebuah A320 Jetstar Japan bisa saja ada di KIX, NRT, HND, FUK, atau CTS. Ekor tetangga Hainan Airlines bisa saja ada di KIX, NRT, atau NGO. Branding jet-bridge SMBC bisa ada di beberapa bandara Jepang. Viaduk horizontal panjang berlatar gunung bisa ada di bandara mana pun yang dibangun di atas lahan reklamasi. Irisan dari "Jetstar Japan A320" ∩ "apron Hainan Airlines" ∩ "jembatan SMBC" ∩ "viaduk Sky Gate Bridge R dengan siluet Izumi" hanya tepat satu bandara: Kansai International Terminal 1.

**Pelajaran umum:** konvergensi multi-sinyal mengalahkan kepastian sinyal-tunggal. Untuk triase dunia nyata mana pun, pola yang disiplin adalah mendaftar setiap sinyal di dalam artefak dan biarkan irisannya yang menyelesaikan pertanyaan, alih-alih berkomitmen pada kecocokan pertama.

## Flag

```
NHNC{20260505_GK55}
```
