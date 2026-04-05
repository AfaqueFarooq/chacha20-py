# RFC 8439 ss.2.3 — State initialization and serialization

from chacha20.constants import MAGIC_CONSTANTS


def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> list[int]:
    """
    Build the initial 16-word ChaCha20 state (flat list).
    All values loaded as little-endian 32-bit words.

    state[0..3]   = MAGIC_CONSTANTS
    state[4..11]  = key (8 words)
    state[12]     = counter
    state[13..15] = nonce (3 words)
    """
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"
    assert len(nonce) == 12, f"Nonce must be 12 bytes, got {len(nonce)}"

    return (
        list(MAGIC_CONSTANTS)
        + [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)]
        + [counter]
        + [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4)]
    )


def serialize_state(state: list[int]) -> bytes:
    """Convert 16-word state into a 64-byte little-endian keystream block."""
    return b"".join(word.to_bytes(4, "little") for word in state)