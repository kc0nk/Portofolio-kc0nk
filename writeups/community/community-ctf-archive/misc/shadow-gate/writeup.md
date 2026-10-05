# Shadow Gate

## Flag

`Null0rigin{sh4d0w_g4t3_br34ch3d_n1c3_0v3rfl0w}`

## Exploit

The authorization input overflows an 80-byte stack buffer. After 88 bytes (buffer plus saved RBP), the ROP chain uses two nearby gadgets to place `0xc0ffee42` in the expected argument register and then returns to the access-granted function. The exploit sends the payload to the challenge TCP service and captures the flag-bearing response.

## Reproduce

Run `exploits/solve_shadow_gate.py` while the service is available. The successful transcript is preserved in `exploits/shadow_gate-response.txt`.

