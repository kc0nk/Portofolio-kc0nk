# Nullwatch

## Flag

`Null0rigin{the_capture_timestamps_were_stretched}`

## Solve

The packet contents are a distraction; the covert data is in capture timing. Normalizing the stretched inter-packet timestamp gaps reveals the encoded bitstream and flag. The recovered flag's SHA-256 matches the verifier digest.

## Reproduce

Run `exploits/nullwatch_packets.py` against the original PCAP. The verified result is in `exploits/20-nullwatch_flag.txt`.

