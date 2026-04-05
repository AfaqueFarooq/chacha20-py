# RFC 8439 ss.2.3 — Block function

from chacha20.primitives import quarter_round
from chacha20.state import chacha20_init_state, serialize_state


def double_round(state: list[int]) -> list[int]:
    """
    One column round + one diagonal round applied in place.

    Columns:   QR(0,4,8,12)  QR(1,5,9,13)  QR(2,6,10,14)  QR(3,7,11,15)
    Diagonals: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13)   QR(3,4,9,14)
    """
    # Columns
    state[0],  state[4],  state[8],  state[12] = quarter_round(state[0],  state[4],  state[8],  state[12])
    state[1],  state[5],  state[9],  state[13] = quarter_round(state[1],  state[5],  state[9],  state[13])
    state[2],  state[6],  state[10], state[14] = quarter_round(state[2],  state[6],  state[10], state[14])
    state[3],  state[7],  state[11], state[15] = quarter_round(state[3],  state[7],  state[11], state[15])
    # Diagonals
    state[0],  state[5],  state[10], state[15] = quarter_round(state[0],  state[5],  state[10], state[15])
    state[1],  state[6],  state[11], state[12] = quarter_round(state[1],  state[6],  state[11], state[12])
    state[2],  state[7],  state[8],  state[13] = quarter_round(state[2],  state[7],  state[8],  state[13])
    state[3],  state[4],  state[9],  state[14] = quarter_round(state[3],  state[4],  state[9],  state[14])
    return state


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    """Generate one 64-byte keystream block."""
    initial = chacha20_init_state(key, counter, nonce)
    working = list(initial)

    for _ in range(10):  # 10 double rounds = 20 total
        double_round(working)

    # feedback: add initial state back mod 2^32 (prevents reversibility)
    working = [(working[i] + initial[i]) & 0xFFFFFFFF for i in range(16)]

    return serialize_state(working)