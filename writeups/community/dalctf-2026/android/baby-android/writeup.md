---
ctf: "DalCTF 2026"
kategori: "Mobile (Android)"
challenge: "Baby Android"
flag: "dalctf{4ndr0id_d3bugg1ng_1s_e4sy}"
teknik: "Flag tertanam statis dalam 3 potongan di MainActivity.java, strings.xml, dan ColorKt.java; tanpa pengecekan runtime maupun obfuskasi"
sumber: "https://github.com/Abdelkad3r/dalctf-2026"
---

# Baby Android — DalCTF 2026 (Android)

## Deskripsi Singkat

Challenge Android level pemula. Handout-nya `BabyAndroid.apk` dengan package `com.example.babyandroid`. Flag-nya **tertanam secara statis** dalam tiga potongan di dalam APK — tanpa pengecekan runtime, tanpa obfuskasi, tanpa anti-debug.

## Recon & Solusi

Dekompilasi sisi resource dan sisi Java:

```
apktool d BabyAndroid.apk -o apk_res    # resource + manifest
jadx -d apk_src BabyAndroid.apk         # dekompilasi Java
```

Tiga potongan flag:

- **`flag1`** — field hardcoded di `MainActivity.java`: `dalctf{4ndr0id`
- **`flag2`** — `res/values/strings.xml`, juga dirujuk sebagai `android:description` pada `MainActivity` di `AndroidManifest.xml`: `_d3bugg1ng_`
- **`flag3`** — field hardcoded di `ui/theme/ColorKt.java`: `_1s_e4sy}`

Gabungkan:

```
dalctf{4ndr0id_d3bugg1ng_1s_e4sy}
```

## Catatan / Insight

Poin belajarnya — dan alasan challenge ini layak dijalankan oleh reviewer Android pemula — adalah bahwa potongan flag suka bersembunyi di resource. `strings.xml`, `colors.xml`, file theme, dan atribut `android:description` / `android:label` di manifest semuanya adalah tempat "grep juga di sini" yang cuma satu langkah. Pipeline review APK yang teliti menjalankan `grep -rE 'dalctf\{|flag' apk_res apk_src` atas seluruh output dekompilasi, bukan cuma file `.java`.

**Kelas bug:** string statis di artefak yang dikirimkan; atribut resource sebagai tempat persembunyian flag.

## Flag

```
dalctf{4ndr0id_d3bugg1ng_1s_e4sy}
```
