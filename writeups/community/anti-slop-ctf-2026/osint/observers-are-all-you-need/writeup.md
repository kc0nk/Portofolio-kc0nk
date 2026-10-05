---
ctf: "Anti-Slop CTF 2026"
kategori: "OSINT"
challenge: "Observers Are All You Need"
flag: "slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs}"
teknik: "Pivot dari prompt kriptik ke project GitHub spesifik, lalu telusuri jejak artefak (profil, issue, PR) satu akun kontributor untuk merangkai 3 fragmen flag"
---

# Observers Are All You Need — Anti-Slop CTF 2026 (OSINT, 443 poin)

## Deskripsi Singkat

Ini varian OSINT bergaya "pivot GitHub": baca prompt kriptik, identifikasi project yang tepat untuk dipivot, lalu telusuri jejak artefak publik project itu (profil, issue, PR) untuk merangkai flag dalam tiga fragmen. Tidak ada bug di sini — soal ini murni pivot GitHub.

## Analisis

Prompt-nya menunjuk ke project spesifik: `FloatingPragma/observer-patch-holography` (OPH), dan flag-nya terpecah jadi tiga fragmen tersembunyi di jenis artefak berbeda pada satu akun kontributor yang sama: `cryptoverse-cyber`.

**Menemukan akun GitHub yang tepat.** Filter kontributor project dan commenter/PR-author terbaru berdasarkan aktivitas di Mei 2026 (window waktu yang diisyaratkan prompt). Satu akun, `cryptoverse-cyber`, punya klaster aktivitas di window itu. Metadata profil publik akun ini adalah tempat pertama untuk mencari fragmen OSINT.

**Tiga fragmen:**
- **Fragmen 1** — blob base64 di field `company` milik profil GitHub.
- **Fragmen 2** — di komentar issue (issue #292).
- **Fragmen 3** — di deskripsi PR (PR #301).

## Eksploitasi / Solusi

Decode ketiga fragmen base64 dan rangkai:

```
slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs}
```

## Catatan / Insight

Petunjuk "tiga bagian" memberi tahu bahwa flag-nya tidak bisa diturunkan hanya dari prosa README repo. Substitusi leetspeak di flag akhir (`rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs`) tidak bisa ditebak dari kalimat "OPH is a reconstruction program for fundamental physics" karena pola substitusinya tidak konsisten. Fragmen-fragmennya harus *ditemukan*, bukan diturunkan.

**Pelajaran lebih luas:** jangan cari kata-kata prompt-nya; cari *artefak tersirat* dari prompt tersebut. Prompt Observers bukan petunjuk yang kamu Google dalam tanda kutip; itu petunjuk tentang project mana yang jadi titik awal jejaknya. Jejak artefak (profil, issue, PR, gist, wiki) adalah permukaan utama OSINT di 2026.

## Flag

```
slopped{OPH_is_a_rec0nstructi0n_pr0gram_f0r_funD4mentaL_phys1cs}
```
