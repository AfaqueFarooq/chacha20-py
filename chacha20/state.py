# chacha20/state.py
# State initialization and serialization
# Reference: RFC 8439 ss.2.3

from chacha20.constants import MAGIC_CONSTANTS


def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    """
    Build the initial 16-word ChaCha20 state matrix.
    All multi-byte values are loaded as little-endian 32-bit words (RFC 8439 ss.2.3).

    Parameters
    ----------
    key     : 32-byte (256-bit) secret key.
    counter : 32-bit block counter (starts at 0 or 1, incremented per block).
    nonce   : 12-byte (96-bit) nonce (must never be reused with the same key).

    Returns
    -------
    List of 16 integers, each a 32-bit word, representing the flat state.

    Layout
    ------
    state[0..3]   = MAGIC_CONSTANTS
    state[4..11]  = key words (8 x 32-bit little-endian)
    state[12]     = counter
    state[13..15] = nonce words (3 x 32-bit little-endian)
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) == 12, f"Nonce must be 12 bytes, got {len(nonce)}"

    state = []

    # words 0-3: magic constants
    state += MAGIC_CONSTANTS

    # words 4-11: key (8 x 32-bit little-endian words)
    state += [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)]

    # word 12: counter
    state.append(counter)

    # words 13-15: nonce (3 x 32-bit little-endian words)
    state += [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4)]

    return state


def serialize_state(state: list[int]) -> bytes:
    """
    Serialize a 16-word state list into a 64-byte little-endian byte string.

    Parameters
    ----------
    state : List of 16 integers, each a 32-bit word.

    Returns
    -------
    64-byte keystream block.
    """
    return b"".join(word.to_bytes(4, "little") for word in state)