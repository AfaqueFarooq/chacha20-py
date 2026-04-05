# RFC 8439 ss.2.4.2 test vectors

from chacha20.cipher import chacha20_encrypt, chacha20_decrypt
from chacha20.block import chacha20_block


def test_encrypt_zeros_equals_keystream():
    key = b"\x00" * 32
    nonce = b"\x00" * 12
    ct = chacha20_encrypt(b"\x00" * 64, key, nonce, 0)
    assert ct == chacha20_block(key, nonce, 0), "Encrypting zeros must equal the raw keystream block"


def test_roundtrip():
    msg = b"Hello, ChaCha20 from RFC 8439!"
    key = bytes(range(32))
    nonce = bytes(range(12))
    assert chacha20_decrypt(chacha20_encrypt(msg, key, nonce, 0), key, nonce, 0) == msg


def test_rfc_8439_vector():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected_ct_hex = (
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )
    ct = chacha20_encrypt(plaintext, key, nonce, 1)
    assert ct.hex() == expected_ct_hex, f"Ciphertext mismatch\nGot:      {ct.hex()}\nExpected: {expected_ct_hex}"


def test_rfc_8439_decrypt():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    ct = chacha20_encrypt(plaintext, key, nonce, 1)
    assert chacha20_decrypt(ct, key, nonce, 1) == plaintext