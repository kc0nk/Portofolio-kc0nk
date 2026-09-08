# π-crypt 0.57

- **Category:** Cryptography

## Ringkasan
Feistel-style transform linear modulo 100; quarter ciphertext leaks the key and the round matrix is invertible.

## Teknik
Recover K → U,V → invert matrix → decrypt.

## Rumus / constraint
```text
Q0 = 33K (mod 100)
K = 97Q0 (mod 100)
U = Q2 - 33K (mod 100)
V = Q3 - 54K (mod 100)
[X,Y]^T = [[34,-21],[-21,13]] [U,V]^T (mod 100)
det = 1 (mod 100)
```

## Solver inti
```python
def pie_crypt(text, key, pie, decrypt=False):
    out = ""; i = sum(base.index(c) for c in key); j = 0
    for c in text:
        d1=int(pie[i%len(pie)]); i+=base.index(key[j%len(key)]); j+=1
        d2=int(pie[i%len(pie)]); i+=base.index(key[j%len(key)]); j+=1
        shift=10*d1+d2
        idx=(base.index(c)-shift)%100 if decrypt else (base.index(c)+shift)%100
        out += base[idx]
    return out
```

## Hasil
```text
brunner{NB!:_Re-using_the_same_key_without_salting-and-hashing_risks_security_of_all_use-instances,_if_one_instance_leaks_info!}
```
