# Carrier

## Flag

`Null0rigin{the_extents_outlived_the_name}`

## Solve

The filesystem directory entries had been removed, but the underlying extents and inodes remained. Restricting recovery to files created during the incident window produced 41 deleted one-byte fragments. Reading those bytes in inode order reconstructed the flag. Its SHA-256 matches the digest embedded in the verifier.

## Reproduce

Use `exploits/carrier_recover.py` for the recovery and `exploits/carrier_ext.py` for extent inspection.

