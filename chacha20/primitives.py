# RFC 8439 ss.2.1 — Core ARX primitives


def rotate_left_32(value: int, n: int) -> int:
    """Circular left-rotation of a 32-bit word by n positions."""
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """
    ChaCha20 quarter round — four ARX steps, all additions mod 2^32.

    a += b; d ^= a; d <<<= 16
    c += d; b ^= c; b <<<= 12
    a += b; d ^= a; d <<<= 8
    c += d; b ^= c; b <<<= 7
    """
    a = (a + b) & 0xFFFFFFFF;  d = d ^ a;  d = rotate_left_32(d, 16)
    c = (c + d) & 0xFFFFFFFF;  b = b ^ c;  b = rotate_left_32(b, 12)
    a = (a + b) & 0xFFFFFFFF;  d = d ^ a;  d = rotate_left_32(d,  8)
    c = (c + d) & 0xFFFFFFFF;  b = b ^ c;  b = rotate_left_32(b,  7)
    return (a, b, c, d)