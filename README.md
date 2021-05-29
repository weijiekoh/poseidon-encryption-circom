# Poseidon encryption on the BN254 elliptic curve

TODO: support BLS12-381 too

The code in this repository implements encryption using Poseidon as described
in [this
paper](https://drive.google.com/file/d/1EVrP3DzoGbmzkRmYnyEDcIQcXVU7GlOd/view).

It also provides an ECDH key deriviation function for public and private keys
on the BabyJub curve.

## Constraints

| Number of message elements | Constraints |
|-|-|
| 1 | 778 |
| 2 | 779 |
| 3 | 778 |
| 4 | 1042 |
| 5 | 1043 |
| 6 | 1042 |
| 7 | 1306 |
| 8 | 1307 |

By comparision, a decryption circuit based on MiMC7 with 5 message elements
uses 1820 constraints.
