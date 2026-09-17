"""Byte-level constants of PBP-1, cipher suite 1.

Changing any value here breaks compatibility with every existing key,
signature and keystore. A new set of algorithms gets a new suite byte instead.
"""

MAGIC = b"PBP1"
SUITE_V1 = 0x01
SIGN_DOMAIN = b"PBP1.sig.v1\x00"

MLDSA_PK_SIZE = 1952
MLDSA_SEED_SIZE = 32
MLDSA_SIG_SIZE = 3309
SLH_PK_SIZE = 32
SLH_SK_SIZE = 64
SLH_SIG_SIZE = 7856

HEADER_SIZE = len(MAGIC) + 1
PUBLIC_KEY_SIZE = HEADER_SIZE + MLDSA_PK_SIZE + SLH_PK_SIZE
SECRET_KEY_SIZE = HEADER_SIZE + MLDSA_SEED_SIZE + SLH_SK_SIZE
SIGNATURE_SIZE = HEADER_SIZE + MLDSA_SIG_SIZE + SLH_SIG_SIZE
