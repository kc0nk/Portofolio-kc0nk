# Brunner Radio

- **Category:** Cryptography

## Ringkasan
Nine transmissions are superposed at positions divisible by their wavelength. This divisibility structure is exactly invertible.

## Teknik
Möbius inversion → recover bit streams → ASCII.

## Rumus / constraint
```text
A(k) = Σ_{i | k} b_i
b_n = A(n) − Σ_{d|n,d<n} b_d
byte = Σ b_r·2^(7-r)
```

## Solver inti
```python
def recover_bits(row,n=9):
    A=[0]+list(map(int,row)); b=[0]*(n+1)
    for k in range(1,n+1):
        b[k]=A[k]-sum(b[d] for d in range(1,k) if k%d==0)
        assert b[k] in (0,1)
    return b[1:]
```

## Hasil
```text
brunner{Brunsviger_is_in_the_air_<3}
```
