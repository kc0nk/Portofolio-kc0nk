# Shredded recipe

- **Category:** Cryptography

## Ringkasan
The 54-byte flag is shredded into three 18-byte streams; each has 15 unknown bytes. The unknowns satisfy one bounded modular linear equation, making lattice/CVP appropriate.

## Teknik
Known prefix/suffix → lattice/CVP → reconstruct three streams → interleave.

## Rumus / constraint
```text
a·x + b·y + c·z ≡ d (mod p)
x = bnr || X
y = rn{ || Y
z = ue || Z || }
X,Y,Z < 2^120
A·X + B·Y + C·Z ≡ D (mod p), C=256c
```

## Solver inti
```python
BND=ZZ(2)^120
A,B,C=ZZ(a),ZZ(b),ZZ(256*c)
L=matrix(ZZ,[[p,0,0,0],[A,1,0,0],[B,0,1,0],[C,0,0,1]])
lat=IntegerLattice(L,lll_reduce=True)
closest=lat.closest_vector(vector(ZZ,[D,0,0,0]))
X,Y,Z=map(ZZ,closest[1:]); assert (A*X+B*Y+C*Z-D)%p==0
```

## Hasil
```text
brunner{i_really_love_solving_equations_with_lattices}
```
