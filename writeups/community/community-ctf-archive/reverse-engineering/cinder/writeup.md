# Cinder

## Flag

`Null0rigin{you_stepped_where_it_would_not_read}`

## Solve

The binary implements five transcript-linked GF(2) systems. The solver reconstructs each layer source from the embedded dump walk, native x87 `fsin`, decrypted VM, scheduler simulation, and executable-range hash. It derives the layer key, verifies its embedded SHA-256 commitment, generates the binary matrix, and solves it with Gaussian elimination over GF(2). Layer five decodes directly to the flag; the four earlier results are verified as hash expansions of that flag.

## Reproduce

Run `exploits/solve_cinder.py` beside the original `NullOrigin_Rev_Chain` directory. `exploits/cinder-layers.json` contains the recovered keys and vectors.

