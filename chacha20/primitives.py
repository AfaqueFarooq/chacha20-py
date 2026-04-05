# chacha20/primitives.py
# Core ARX primitives: rotate_left_32 and quarter_round
# Reference: RFC 8439 ss.2.1


def rotate_left_32(value: int, n: int) -> int:
    """
    Circular left-rotation of a 32-bit word by n positions.

    Example:
        rotate_left_32(0x00000001, 1)  == 0x00000002
        rotate_left_32(0x80000000, 1)  == 0x00000001   (MSB wraps to LSB)
        rotate_left_32(0x12345678, 16) == 0x56781234

    Parameters
    ----------
    value : 32-bit input word (Python integer).
    n     : Number of positions to rotate left (0 <= n < 32).

    Returns
    -------
    32-bit rotated word.
    """
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


def quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """
    Apply the ChaCha20 quarter round to four 32-bit words.

    The four ARX steps (all additions mod 2^32):
        a = (a + b) & 0xffffffff;  d ^= a;  d = rotate_left_32(d, 16)
        c = (c + d) & 0xffffffff;  b ^= c;  b = rotate_left_32(b, 12)
        a = (a + b) & 0xffffffff;  d ^= a;  d = rotate_left_32(d,  8)
        c = (c + d) & 0xffffffff;  b ^= c;  b = rotate_left_32(b,  7)

    Parameters
    ----------
    a, b, c, d : Four 32-bit input words (Python integers).

    Returns
    -------
    Tuple (a, b, c, d) of four 32-bit output words.
    """
    a = (a + b) & 0xFFFFFFFF;  d = d ^ a;  d = rotate_left_32(d, 16)
    c = (c + d) & 0xFFFFFFFF;  b = b ^ c;  b = rotate_left_32(b, 12)
    a = (a + b) & 0xFFFFFFFF;  d = d ^ a;  d = rotate_left_32(d,  8)
    c = (c + d) & 0xFFFFFFFF;  b = b ^ c;  b = rotate_left_32(b,  7)
    return (a, b, c, d)