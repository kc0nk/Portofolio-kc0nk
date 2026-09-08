# Slis

- **Category:** Cryptography

## Ringkasan
The 9^5 floor-difference sum telescopes to two terms, so the huge-looking challenge reduces to an exact integer equation.

## Teknik
Telescoping sum + integer division inversion.

## Rumus / constraint
```text
Σ(⌊n/(i+2)⌋−⌊n/(i+3)⌋)=⌊n/2⌋−⌊n/59051⌋
q=⌊(2S+b)/59049⌋, b∈{0,1}
```

## Solver inti
```python
S=22263691028918788395010325066307464924652601045336492930678310479674861811846
M=59051
for b in (0,1):
    q=(2*S+b)//(M-2); n=2*(S+q)+b
    if n//2-n//M==S:
        raw=n.to_bytes((n.bit_length()+7)//8,'big')
        if raw.startswith(b'brunner{') and raw.endswith(b'}'): print(raw.decode())
```

## Hasil
```text
brunner{Pease_porridge_sHOrT_:)}
```
