# RFC 8439 ss.2.4 — Stream cipher

from chacha20.block import chacha20_block


def chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    """
    Encrypt an arbitrary-length message with ChaCha20.
    XORs each 64-byte chunk with a keystream block (counter increments per block).
    Decryption is identical — just call this function again.
    """
    ciphertext = []
    for i, offset in enumerate(range(0, len(plaintext), 64)):
        chunk = plaintext[offset:offset + 64]
        keystream = chacha20_block(key, nonce, counter + i)
        ciphertext.append(bytes(p ^ k for p, k in zip(chunk, keystream)))
    return b"".join(ciphertext)


def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    """Decrypt a ChaCha20 ciphertext — identical to encryption."""
    return chacha20_encrypt(ciphertext, key, nonce, counter)