# tests/test_block.py
# RFC 8439 ss.2.3.2 test vectors

from chacha20.block import double_round, chacha20_block


def test_double_round_alters_state():
    state = list(range(16))
    state[0] = 0x61707865
    double_round(state)
    assert any(w != i for i, w in enumerate(state)), "double_round must alter the state"


def test_chacha20_block_length():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, nonce, 1)
    assert len(block) == 64, "Block must be exactly 64 bytes"


def test_chacha20_block_rfc_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    block = chacha20_block(key, nonce, 1)

    expected_words = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ]

    got_words = [int.from_bytes(block[i*4:(i+1)*4], "little") for i in range(16)]
    assert got_words == expected_words, "Block mismatch at word(s): " + str(
        [i for i in range(16) if got_words[i] != expected_words[i]]
    )