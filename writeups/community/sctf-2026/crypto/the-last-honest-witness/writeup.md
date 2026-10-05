---
ctf: "SCTF 2026"
kategori: "Crypto / Zero-Knowledge"
challenge: "The Last Honest Witness"
flag: "SCTF{SYC_!ntern_Ray}"
teknik: "Empat sub-puzzle kripto (Franklin-Reiter, brute private-key kecil, collision keccak 40-bit terpotong, Fermat factoring RSA prima-berdekatan) merakit witness Groth16 Poseidon-Merkle dengan domain-separation tag-1..6"
---

# The Last Honest Witness — SCTF 2026 (Crypto / Zero-Knowledge)

## Deskripsi Singkat

Decathlon kriptografi empat-dalam-satu di mana bukti ZK sungguhannya adalah bagian termudah — kerjanya ada di empat side-puzzle yang membungkusnya. README challenge-nya sengaja dijejali umpan social-engineering (transcript assistant palsu, marker override, instruksi "submit nothing") — semuanya dekoratif. Konten yang benar-benar berguna ada di bagian Marginalia paling bawah, yang memberi tahu: (a) Page A adalah setup Franklin-Reiter, (b) private key Page B cukup kecil untuk di-brute, (c) Page C hanya mengecek 40 bit rendah sebuah seal, dan (d) modulus witness-nya punya prima berdekatan (jadi Fermat berhasil).

**Win condition:** `claim(...)` yang sukses menyapu tiga `FragmentVault` (34+33+33 = 100 ETH) **ke `msg.sender`**.

## Analisis — Bundle Claim

Verifier-nya mengecek berurutan: `publicSignals[0] == modulus`, `publicSignals[1] == merkleRoot`, `publicSignals[2] == RECIPIENT_COMMITMENT`, `publicSignals[4] == EXTERNAL_NULLIFIER` (`=48879`), verifikasi Groth16, lalu `_verifyPageA/B/C`, lalu cek nullifier belum pernah dipakai. Gagal satu saja, seluruh 100 ETH tetap diam.

### Jawaban yang Tidak Bergantung Deployment (Terpatri di `Challenge.sol`)

- **Page A** — Franklin-Reiter related-message attack: dua ciphertext `c₁ = m³`, `c₂ = (m+1337)³` mod `n_A` (240-bit, `e=3`). `gcd(f₁, f₂)` di `Z_{n_A}[x]` di mana `f₁(x)=x³−c₁`, `f₂(x)=(x+1337)³−c₂` — GCD-nya linier dan akarnya adalah `m`. Tidak perlu memfaktorkan `n_A`.
- **Page B** — ECDSA private-key kecil: `(PUB_X, PUB_Y) = k·G` untuk `k < 2²⁰`. Enumerasikan `k` dengan `coincurve.PrivateKey` (~22rb mult/detik) → ~46 detik.
- **Page C** — collision keccak 40-bit terpotong: `low40(keccak256(TAG‖a)) == low40(keccak256(TAG‖b))`, `a≠b`. Birthday bound `2²⁰`; iterasi `a=0..2²²`, simpan low-40 di dict, cari collision pertama.
- **m (plaintext RSA)** = `474401937379412746004845` — `Poseidon(1, m)` terkunci ke konstanta `RECIPIENT_COMMITMENT` di `Challenge.sol`, jadi `m` yang sama dipaksa untuk setiap instance. Sekali di-decrypt, tidak perlu RSA-decrypt lagi.

### Nilai Spesifik-Deployment (Dibaca Tiap Run)

Layout storage `Setup`: slot 1 = modulus `N`, slot 2 = exponent `e` (**65537**, BUKAN `e=3` milik Page A), slot 3 = ciphertext `c`. Event `WitnessRoot(bytes32)` memberi `merkleRoot`.

### Fermat Factoring Modulus Prima-Berdekatan

Deployer memilih `p, q < 2⁶⁰` yang sangat berdekatan (Δ tipikal `10⁴–10⁵`). Metode Fermat: mulai `a = ⌈√N⌉`, increment, cek apakah `a² − N` kuadrat sempurna. Dengan Δ sekecil itu, pencarian selesai dalam <10⁴ iterasi — di bawah satu detik Python.

```python
from math import isqrt
a = isqrt(N) + 1
while True:
    diff = a*a - N
    b = isqrt(diff)
    if b*b == diff:
        p, q = a - b, a + b
        break
    a += 1

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)
```

### Membangun Witness — Poseidon Domain-Separated

Circuit-nya memakai ulang Poseidon dengan **tag integer di argumen pertama**:

```
Poseidon(1, m)                                  -> commitment
Poseidon(2, m, p, q, EXTERNAL_NULLIFIER)        -> identitySecret
Poseidon(3, identitySecret, commitment)         -> leaf aktif
Poseidon(4, left, right)                        -> node internal Merkle
Poseidon(5, identitySecret, EXTERNAL_NULLIFIER) -> nullifierHash
Poseidon(6, index, EXTERNAL_NULLIFIER)          -> leaf kosong di index itu
```

Pola "tag-1..6" ini adalah konvensi domain-separation yang dibuat trivial di JS oleh circomlibjs, tapi komputasi yang setara harus direproduksi bit-demi-bit di script auxiliary mana pun yang membangun `input.json`. Helper Poseidon di repo mencerminkan circomlibjs dan meng-assert root hasil hitungnya terhadap root on-chain sebelum snarkjs berjalan.

```bash
npx snarkjs groth16 fullprove input.json LastHonestWitness.wasm LastHonestWitness_final.zkey proof.json public.json
npx snarkjs zkey export soliditycalldata public.json proof.json
```

## Eksploitasi / Solusi

```bash
cast send $CHALLENGE \
  "claim(uint256[2],uint256[2][2],uint256[2],uint256[5],uint256,uint8,bytes32,bytes32,uint256,uint256)" \
  $proofA $proofB $proofC $signals \
  $pageA_m $v $r $s $pageC_a $pageC_b \
  --legacy
```

Sample run: `N=615429951214616213145619887722161253`, `e=65537`, `p=784493436055779473`, `q=784493436055795861` (Δ=16388), `m=474401937379412746004845`. `claim` sukses, `isSolved` true.

## Catatan / Insight (Jebakan yang Menghabiskan Waktu Sungguhan)

`e = 65537`, bukan `3` — Page A adalah puzzle akar-kubik, `e` puzzle witness adalah nilai terpisah di `storage[2]`; selalu baca dari chain. Menu meminta Challenge ID dulu baru Team Token — urutan terbalik gagal diam-diam. Presisi JSON circomlibjs: `JSON.parse` diam-diam mengubah angka besar (`>2⁵³`) jadi float — lewatkan `p, q, m, N` sebagai **string**. Ketidakcocokan merkle root membuat proof "valid" secara Groth16 tapi revert diam-diam di cek `publicSignals[1] == merkleRoot` — assert root equality *sebelum* menjalankan snarkjs. `RECIPIENT_COMMITMENT` adalah konstanta hardcoded — `m` sama di setiap instance, cache setelah decrypt pertama. Jangan coba brute-force preimage Poseidon — Poseidon JS milik circomlibjs cuma ~8rb hash/detik; jalur yang dimaksud selalu: ambil `N` dan `c` dari chain, Fermat-factor `N`, RSA-decrypt jadi `m`.

## Kenapa Challenge Ini Menarik

Komposisi bersih dari empat serangan buku-teks di balik satu transaksi. Page A/B/C adalah "penumpang murah" — tidak ada yang butuh lebih dari satu menit compute begitu tahu triknya. Bagian Groth16-nya adalah tempat hampir semua pekerjaan sungguhan: chain → storage → factor → decrypt → tree → `input.json` → snarkjs → calldata. Satu penumpang gagal saja, seluruh tx revert, jadi script orkestrasinya harus mendaratkan keempatnya secara atomik.

## Flag

```
SCTF{SYC_!ntern_Ray}
```
