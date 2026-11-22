"""QR Code Model 2 encoder (ISO/IEC 18004), byte mode, rendered as SVG.

Standard library only. Supports versions 1-40 and error correction levels
L/M/Q/H; the panel uses it for otpauth:// URIs and tailnet enrolment data.
Structure follows the reference algorithm published by Project Nayuki (MIT).
"""

from __future__ import annotations

# Index 0 is unused; [level][version], levels in order L, M, Q, H.
_ECC_CODEWORDS_PER_BLOCK = (
    (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30,
     30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
)
_NUM_ERROR_CORRECTION_BLOCKS = (
    (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18,
     19, 19, 20, 21, 22, 24, 25),
    (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31,
     33, 35, 37, 38, 40, 43, 45, 47, 49),
    (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40,
     43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48,
     51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
)
# Level -> (table index, 2-bit format value).
_LEVELS = {"L": (0, 1), "M": (1, 0), "Q": (2, 3), "H": (3, 2)}
MIN_VERSION, MAX_VERSION = 1, 40
_PENALTY_N1, _PENALTY_N2, _PENALTY_N3, _PENALTY_N4 = 3, 3, 40, 10


class DataTooLong(ValueError):
    pass


def _gf_multiply(x: int, y: int) -> int:
    """Product in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1."""
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_multiply(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_multiply(root, 0x02)
    return result


def _rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        for i, coefficient in enumerate(divisor):
            result[i] ^= _gf_multiply(coefficient, factor)
    return result


def _num_raw_data_modules(version: int) -> int:
    result = (16 * version + 128) * version + 64
    if version >= 2:
        num_align = version // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if version >= 7:
            result -= 36
    return result


def _num_data_codewords(version: int, level: int) -> int:
    return (_num_raw_data_modules(version) // 8
            - _ECC_CODEWORDS_PER_BLOCK[level][version] * _NUM_ERROR_CORRECTION_BLOCKS[level][version])


def _alignment_positions(version: int) -> list[int]:
    if version == 1:
        return []
    num_align = version // 7 + 2
    step = (version * 8 + num_align * 3 + 5) // (num_align * 4 - 4) * 2
    result = [version * 4 + 10 - i * step for i in range(num_align - 1)] + [6]
    return list(reversed(result))


def _bit(value: int, index: int) -> bool:
    return (value >> index) & 1 != 0


class QrCode:
    """An immutable QR symbol: `size` x `size` boolean modules (True = dark)."""

    def __init__(self, version: int, level: str, codewords: list[int], mask: int | None):
        self.version = version
        self.level = level
        self.size = version * 4 + 17
        self._level_index, self._format_level = _LEVELS[level]
        self.modules = [[False] * self.size for _ in range(self.size)]
        self._function = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()
        self._draw_codewords(self._add_ecc_and_interleave(codewords))
        if mask is None:
            best_penalty = None
            for candidate in range(8):
                self._apply_mask(candidate)
                self._draw_format_bits(candidate)
                penalty = self._penalty_score()
                if best_penalty is None or penalty < best_penalty:
                    mask, best_penalty = candidate, penalty
                self._apply_mask(candidate)  # XOR again undoes it
        assert mask is not None and 0 <= mask <= 7
        self.mask = mask
        self._apply_mask(mask)
        self._draw_format_bits(mask)
        del self._function

    # --- function patterns ---------------------------------------------------------
    def _set_function(self, x: int, y: int, dark: bool) -> None:
        self.modules[y][x] = dark
        self._function[y][x] = True

    def _draw_function_patterns(self) -> None:
        size = self.size
        for i in range(size):
            self._set_function(6, i, i % 2 == 0)
            self._set_function(i, 6, i % 2 == 0)
        self._draw_finder(3, 3)
        self._draw_finder(size - 4, 3)
        self._draw_finder(3, size - 4)
        positions = _alignment_positions(self.version)
        last = len(positions) - 1
        for i, px in enumerate(positions):
            for j, py in enumerate(positions):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                self._draw_alignment(px, py)
        self._draw_format_bits(0)  # reserve the area; real bits are drawn after masking
        self._draw_version()

    def _draw_finder(self, x: int, y: int) -> None:
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                xx, yy = x + dx, y + dy
                if 0 <= xx < self.size and 0 <= yy < self.size:
                    self._set_function(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))

    def _draw_alignment(self, x: int, y: int) -> None:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self._set_function(x + dx, y + dy, max(abs(dx), abs(dy)) != 1)

    def _draw_format_bits(self, mask: int) -> None:
        data = self._format_level << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        size = self.size
        for i in range(0, 6):
            self._set_function(8, i, _bit(bits, i))
        self._set_function(8, 7, _bit(bits, 6))
        self._set_function(8, 8, _bit(bits, 7))
        self._set_function(7, 8, _bit(bits, 8))
        for i in range(9, 15):
            self._set_function(14 - i, 8, _bit(bits, i))
        for i in range(0, 8):
            self._set_function(size - 1 - i, 8, _bit(bits, i))
        for i in range(8, 15):
            self._set_function(8, size - 15 + i, _bit(bits, i))
        self._set_function(8, size - 8, True)  # dark module

    def _draw_version(self) -> None:
        if self.version < 7:
            return
        rem = self.version
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = self.version << 12 | rem
        for i in range(18):
            dark = _bit(bits, i)
            a, b = self.size - 11 + i % 3, i // 3
            self._set_function(a, b, dark)
            self._set_function(b, a, dark)

    # --- data ----------------------------------------------------------------------
    def _add_ecc_and_interleave(self, data: list[int]) -> list[int]:
        version, level = self.version, self._level_index
        num_blocks = _NUM_ERROR_CORRECTION_BLOCKS[level][version]
        block_ecc_len = _ECC_CODEWORDS_PER_BLOCK[level][version]
        raw_codewords = _num_raw_data_modules(version) // 8
        num_short_blocks = num_blocks - raw_codewords % num_blocks
        short_block_len = raw_codewords // num_blocks
        divisor = _rs_divisor(block_ecc_len)
        blocks = []
        k = 0
        for i in range(num_blocks):
            length = short_block_len - block_ecc_len + (0 if i < num_short_blocks else 1)
            block = data[k:k + length]
            k += length
            ecc = _rs_remainder(block, divisor)
            if i < num_short_blocks:
                block.append(0)
            blocks.append(block + ecc)
        result = []
        for i in range(len(blocks[0])):
            for j, block in enumerate(blocks):
                if i != short_block_len - block_ecc_len or j >= num_short_blocks:
                    result.append(block[i])
        return result

    def _draw_codewords(self, data: list[int]) -> None:
        size = self.size
        i = 0
        right = size - 1
        total_bits = len(data) * 8
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = (right + 1) & 2 == 0
                    y = size - 1 - vert if upward else vert
                    if not self._function[y][x] and i < total_bits:
                        self.modules[y][x] = _bit(data[i >> 3], 7 - (i & 7))
                        i += 1
            right -= 2

    def _apply_mask(self, mask: int) -> None:
        conditions = (
            lambda x, y: (x + y) % 2 == 0,
            lambda x, y: y % 2 == 0,
            lambda x, y: x % 3 == 0,
            lambda x, y: (x + y) % 3 == 0,
            lambda x, y: (x // 3 + y // 2) % 2 == 0,
            lambda x, y: x * y % 2 + x * y % 3 == 0,
            lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
        )
        condition = conditions[mask]
        for y in range(self.size):
            row, function = self.modules[y], self._function[y]
            for x in range(self.size):
                if not function[x] and condition(x, y):
                    row[x] = not row[x]

    # --- mask penalty ------------------------------------------------------------
    def _penalty_score(self) -> int:
        size, modules = self.size, self.modules
        result = 0
        for lines in (modules, [list(col) for col in zip(*modules)]):
            for line in lines:
                run_color = False
                run_len = 0
                history = [0] * 7
                for color in line:
                    if color == run_color:
                        run_len += 1
                        if run_len == 5:
                            result += _PENALTY_N1
                        elif run_len > 5:
                            result += 1
                    else:
                        self._history_add(run_len, history)
                        if not run_color:
                            result += self._finder_like(history) * _PENALTY_N3
                        run_color = color
                        run_len = 1
                result += self._history_terminate(run_color, run_len, history) * _PENALTY_N3
        for y in range(size - 1):
            for x in range(size - 1):
                color = modules[y][x]
                if color == modules[y][x + 1] == modules[y + 1][x] == modules[y + 1][x + 1]:
                    result += _PENALTY_N2
        dark = sum(sum(1 for c in row if c) for row in modules)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        result += k * _PENALTY_N4
        return result

    def _history_add(self, run_len: int, history: list[int]) -> None:
        if history[0] == 0:
            run_len += self.size  # light border before the first run
        history.pop()
        history.insert(0, run_len)

    def _history_terminate(self, run_color: bool, run_len: int, history: list[int]) -> int:
        if run_color:
            self._history_add(run_len, history)
            run_len = 0
        run_len += self.size  # light border after the last run
        self._history_add(run_len, history)
        return self._finder_like(history)

    @staticmethod
    def _finder_like(history: list[int]) -> int:
        n = history[1]
        core = n > 0 and history[2] == history[4] == history[5] == n and history[3] == n * 3
        return ((1 if core and history[0] >= n * 4 and history[6] >= n else 0)
                + (1 if core and history[6] >= n * 4 and history[0] >= n else 0))

    # --- output ----------------------------------------------------------------------
    def to_svg(self, border: int = 4, module_px: int = 6, title: str = "Kod QR") -> str:
        """Standalone inline SVG (no scripts, no external references)."""
        from html import escape

        dim = self.size + border * 2
        parts = []
        for y, row in enumerate(self.modules):
            x = 0
            while x < self.size:
                if row[x]:
                    start = x
                    while x < self.size and row[x]:
                        x += 1
                    parts.append(f"M{start + border},{y + border}h{x - start}v1h-{x - start}z")
                else:
                    x += 1
        pixels = dim * module_px
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" width="{pixels}" height="{pixels}" '
            f'role="img" aria-label="{escape(title)}" shape-rendering="crispEdges">'
            f"<title>{escape(title)}</title>"
            f'<rect width="{dim}" height="{dim}" fill="#ffffff"/>'
            f'<path d="{"".join(parts)}" fill="#000000"/></svg>'
        )


def encode(data: bytes | str, level: str = "M", *, min_version: int = MIN_VERSION, mask: int | None = None) -> QrCode:
    """Encode `data` in byte mode at the smallest version that fits."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if level not in _LEVELS:
        raise ValueError("level must be L, M, Q or H")
    if not MIN_VERSION <= min_version <= MAX_VERSION:
        raise ValueError("min_version out of range")
    if mask is not None and not 0 <= mask <= 7:
        raise ValueError("mask must be 0..7")
    level_index = _LEVELS[level][0]
    for version in range(min_version, MAX_VERSION + 1):
        count_bits = 8 if version <= 9 else 16
        capacity_bits = _num_data_codewords(version, level_index) * 8
        used_bits = 4 + count_bits + len(data) * 8
        if len(data) < (1 << count_bits) and used_bits <= capacity_bits:
            break
    else:
        raise DataTooLong("data does not fit in a QR code")
    bits: list[int] = []

    def append(value: int, length: int) -> None:
        bits.extend((value >> i) & 1 for i in reversed(range(length)))

    append(0b0100, 4)  # byte mode
    append(len(data), count_bits)
    for byte in data:
        append(byte, 8)
    append(0, min(4, capacity_bits - len(bits)))
    append(0, -len(bits) % 8)
    pad = 0xEC
    while len(bits) < capacity_bits:
        append(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    return QrCode(version, level, codewords, mask)


def svg(data: bytes | str, level: str = "M", title: str = "Kod QR") -> str:
    return encode(data, level).to_svg(title=title)
