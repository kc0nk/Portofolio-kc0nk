---
ctf: "BYUCTF 2026"
kategori: "Reverse Engineering"
challenge: "Angr Management"
flag: "byuctf{g3t_w1th_th3_c0ntr01_fl0w}"
teknik: "Directed graph 625-node; BFS dari 0 ke 624 mereproduksi urutan input yang dibutuhkan"
---

# Angr Management — BYUCTF 2026 (Reverse Engineering)

## Deskripsi Singkat

Binary remote-nya adalah directed graph dari 625 blok. Setiap blok mencetak `"Arrived at N"`, membaca sebuah integer, dan `jmp` ke neighbour mana pun yang cocok. Blok 624 (`0x270`) mencetak flag-nya.

## Analisis

Nama challenge-nya adalah umpan — `angr` memang bisa menyelesaikannya, tapi setiap blok punya bentuk yang sama, jadi dua regex atas `objdump -d` mengekstrak seluruh graph-nya:

```text
nodeN_head:
    movl   $N, %esi
    leaq   <0xf019>(%rip), %rax        ; "Arrived at %d"
    callq  printf
    callq  get_input
    cmpl   $TARGET_1, -0x4(%rbp)
    je     blockA
    cmpl   $TARGET_2, -0x4(%rbp)
    je     blockB
    …
```

## Eksploitasi / Solusi

Ekstrak adjacency list secara statis, BFS dari 0 ke 624, replay urutan integer-nya lewat socket:

```
byuctf{g3t_w1th_th3_c0ntr01_fl0w}
```

## Catatan / Insight

**Pelajaran untuk defender:** "mengaburkan control flow" hanya separuh pertahanan. Kalau dispatch-nya cukup teratur untuk di-disassembly dengan dua regex, itu cukup teratur juga untuk di-BFS.

## Flag

```
byuctf{g3t_w1th_th3_c0ntr01_fl0w}
```
