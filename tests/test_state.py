# tests/test_state.py
# RFC 8439 ss.2.3.2 test vectors

from chacha20.state import chacha20_init_state, serialize_state


def test_init_state_constants():
    key = bytes(range(32))
    nonce = bytes([0] * 12)
    state = chacha20_init_state(key, 0, nonce)

    assert len(state) == 16
    assert state[0] == 0x61707865, "Constant word 0 wrong"
    assert state[1] == 0x3320646E, "Constant word 1 wrong"
    assert state[2] == 0x79622D32, "Constant word 2 wrong"
    assert state[3] == 0x6B206574, "Constant word 3 wrong"


def test_init_state_key_endianness():
    key = bytes(range(32))
    nonce = bytes([0] * 12)
    state = chacha20_init_state(key, 0, nonce)
    assert state[4] == 0x03020100, "Key word 0 wrong (check endianness)"
    assert state[12] == 0, "Counter must be 0"


def test_serialize_state_roundtrip():
    key = bytes(range(32))
    nonce = bytes([0] * 12)
    state = chacha20_init_state(key, 0, nonce)
    serialized = serialize_state(state)

    assert len(serialized) == 64
    assert int.from_bytes(serialized[0:4], "little") == 0x61707865
    assert int.from_bytes(serialized[16:20], "little") == 0x03020100


def test_init_state_nonce_placement():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    state = chacha20_init_state(key, 1, nonce)

    assert state[12] == 1
    assert state[13] == 0x09000000, "Nonce word 0 wrong (little-endian!)"
    assert state[14] == 0x4A000000, "Nonce word 1 wrong (little-endian!)"
    assert state[15] == 0x00000000, "Nonce word 2 wrong"