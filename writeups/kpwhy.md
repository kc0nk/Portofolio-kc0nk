# KPWhy

- **Category:** Reverse Engineering
- **Status:** FULL TRANSCRIPT EXTRACTED

## Ringkasan
ELF x86-64 tidak stripped dengan tiga validator: `calculateSynergy`, `measureVelocity`, `assessAlignment`. Ketiganya harus bernilai 1 dan panjang ID harus 44 byte.

## Metode
Balik constraint byte-wise, lalu inverse lookup terhadap synergy table.

## Command / primitive
```c
fgets(buf, 0x100, stdin)
strlen(input) == 44
calculateSynergy + measureVelocity + assessAlignment == 3
```

## Rumus / constraint
```text
input[i] = alpha[i] XOR ((7*i + 42) & 0xff)
input[i] + input[i-1] = beta[i-15]
synergy_table[input[i]] = gamma[i-30]
```

## Solver / code snippet
```python
for i, target in enumerate(ALPHA):
    result.append(target ^ ((7*i + 42) & 0xff))
for target in BETA:
    result.append((target - result[-1]) & 0xff)
inverse = {value: i for i, value in enumerate(SYNERGY_TABLE)}
for target in GAMMA:
    result.append(inverse[target])
```

## Hasil
```text
brunner{y0ur_kp1s_ar3_n0t_l00king_gr8_buddy}
```
