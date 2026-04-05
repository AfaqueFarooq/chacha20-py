# chacha20/block.py
# Block function: double_round and chacha20_block
# Reference: RFC 8439 ss.2.3

from chacha20.primitives import quarter_round
from chacha20.state import chacha20_init_state, serialize_state


def double_round(state: list[int]) -> list[int]:
    """
    Apply one ChaCha20 double round (column round + diagonal round) in place.
    Modifies the state list in place AND returns it.

    Column round -- quarter round on each column of the 4x4 state:
        QR(state[0],  state[4],  state[8],  state[12])
        QR(state[1],  state[5],  state[9],  state[13])
        QR(state[2],  state[6],  state[10], state[14])
        QR(state[3],  state[7],  state[11], state[15])

    Diagonal round -- quarter round on each diagonal:
        QR(state[0],  state[5],  state[10], state[15])
        QR(state[1],  state[6],  state[11], state[12])
        QR(state[2],  state[7],  state[8],  state[13])
        QR(state[3],  state[4],  state[9],  state[14])

    Parameters
    ----------
    state : Mutable list of 16 32-bit words (modified in place).

    Returns
    -------
    The same list after applying both rounds (for convenience).
    """
    # Column round
    state[0],  state[4],  state[8],  state[12] = quarter_round(state[0],  state[4],  state[8],  state[12])
    state[1],  state[5],  state[9],  state[13] = quarter_round(state[1],  state[5],  state[9],  state[13])
    state[2],  state[6],  state[10], state[14] = quarter_round(state[2],  state[6],  state[10], state[14])
    state[3],  state[7],  state[11], state[15] = quarter_round(state[3],  state[7],  state[11], state[15])

    # Diagonal round
    state[0],  state[5],  state[10], state[15] = quarter_round(state[0],  state[5],  state[10], state[15])
    state[1],  state[6],  state[11], state[12] = quarter_round(state[1],  state[6],  state[11], state[12])
    state[2],  state[7],  state[8],  state[13] = quarter_round(state[2],  state[7],  state[8],  state[13])
    state[3],  state[4],  state[9],  state[14] = quarter_round(state[3],  state[4],  state[9],  state[14])

    return state


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """
    Generate one 64-byte ChaCha20 keystream block.

    Steps:
    1. Build initial state from key, counter, nonce.
    2. Copy initial state into working state.
    3. Apply double_round 10 times (= 20 rounds total).
    4. Add initial state to working state word-by-word (mod 2^32).
    5. Serialize and return 64 bytes.

    Parameters
    ----------
    key     : 32-byte secret key.
    nonce   : 12-byte nonce.
    counter : 32-bit block counter.

    Returns
    -------
    64-byte keystream block.
    """
    initial_state = chacha20_init_state(key, counter, nonce)

    working_state = list(initial_state)  # make a copy

    for _ in range(10):
        double_round(working_state)

    # add initial state back word-by-word mod 2^32
    working_state = [(working_state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]

    return serialize_state(working_state)