# Greylist

## Flag

`Null0rigin{the_second_buffer_never_ran}`

## Solve

The memory image contains two same-sized hidden buffers. XORing the correct pair removes their common background and leaves a monochrome bitmap. Rendering that bitmap reveals the flag. Its SHA-256 matches the challenge verifier.

## Reproduce

Use `exploits/greylist_pair.py` and `exploits/greylist_xor.py` to compare the buffers, then `exploits/greylist_bitmap.py` to render the result.

