# chacha20-py

A clean Python implementation of the ChaCha20 stream cipher from scratch, following [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

Built entirely from 32-bit integer additions, XOR, and bitwise rotations — no lookup tables, no S-boxes.

## Structure

```
chacha20/
├── constants.py   # Magic constants ("expand 32-byte k")
├── primitives.py  # rotate_left_32, quarter_round
├── state.py       # chacha20_init_state, serialize_state
├── block.py       # double_round, chacha20_block
└── cipher.py      # chacha20_encrypt, chacha20_decrypt
```

## Usage

```python
from chacha20.cipher import chacha20_encrypt, chacha20_decrypt

key   = bytes(range(32))   # 32 bytes
nonce = bytes(range(12))   # 12 bytes, never reuse with same key

ct = chacha20_encrypt(b"Hello, ChaCha20!", key, nonce, counter=1)
pt = chacha20_decrypt(ct, key, nonce, counter=1)
```

## Run Tests

```bash
pytest tests/ -v
```

All 13 tests verified against official RFC 8439 test vectors.

## How It Works

1. **State** — 4×4 matrix of 32-bit words built from key, counter, and nonce
2. **Quarter round** — core ARX (Add, Rotate, XOR) mixing function
3. **Block** — 10 double rounds (20 total) + feedback addition → 64-byte keystream
4. **Cipher** — XOR keystream with plaintext, incrementing counter per 64-byte chunk

## Reference

- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)