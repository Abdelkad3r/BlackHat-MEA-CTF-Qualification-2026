#!/usr/bin/env python3
"""Dependency-free reader for WinZip-AES encrypted ZIP archives (AE-1 / AE-2).

pyzipper writes the WinZip AES extension, which stock `zipfile` cannot read:
`compress_type` is the sentinel 99 and the real method hides in an 0x9901 extra
field. Everything needed to undo it is in the standard library except AES
itself, so a compact encrypt-only AES lives here too (CTR mode only ever calls
the forward transform).

Container layout of an encrypted member, per the WinZip AE spec:

    [ salt | pv | ciphertext | auth ]
      ^      ^                 ^
      |      |                 `- HMAC-SHA1(key_hmac, ciphertext)[:10]
      |      `- 2-byte password verifier
      `- 8 / 12 / 16 bytes for AES-128 / 192 / 256

    PBKDF2-HMAC-SHA1(password, salt, 1000, 2*ks + 2)
        -> key_aes (ks) || key_hmac (ks) || pv (2)

The keystream is AES-CTR with a *little-endian* counter that starts at 1.
"""

import hashlib
import hmac
import struct
import zlib

# --------------------------------------------------------------------------
# AES (encrypt only)
# --------------------------------------------------------------------------

_SBOX = bytearray(256)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _build_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6))
        x ^= ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        _SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    _SBOX[0] = 0x63


_build_sbox()


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


class AES:
    """Minimal AES block cipher. Only `encrypt_block` is implemented."""

    def __init__(self, key):
        nk = len(key) // 4
        if nk not in (4, 6, 8):
            raise ValueError("key must be 16, 24 or 32 bytes")
        self.rounds = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (self.rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        self.rk = w

    def _add_round_key(self, s, rnd):
        for c in range(4):
            k = self.rk[rnd * 4 + c]
            for r in range(4):
                s[r][c] ^= k[r]

    def encrypt_block(self, block):
        s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_round_key(s, 0)
        for rnd in range(1, self.rounds + 1):
            for r in range(4):
                for c in range(4):
                    s[r][c] = _SBOX[s[r][c]]
            for r in range(1, 4):                       # ShiftRows
                s[r] = s[r][r:] + s[r][:r]
            if rnd != self.rounds:                      # MixColumns
                for c in range(4):
                    a = [s[r][c] for r in range(4)]
                    x = a[0] ^ a[1] ^ a[2] ^ a[3]
                    for r in range(4):
                        s[r][c] ^= x ^ _xtime(a[r] ^ a[(r + 1) % 4])
            self._add_round_key(s, rnd)
        return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_ctr_winzip(key, data):
    """WinZip's CTR variant: 16-byte LE counter, first block uses counter = 1."""
    aes = AES(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = aes.encrypt_block(struct.pack("<QQ", i // 16 + 1, 0))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


# --------------------------------------------------------------------------
# ZIP container
# --------------------------------------------------------------------------

_SALT_LEN = {1: 8, 2: 12, 3: 16}
_KEY_LEN = {1: 16, 2: 24, 3: 32}

_EOCD = b"PK\x05\x06"
_CEN = b"PK\x01\x02"


class Member:
    __slots__ = ("name", "offset", "comp_size", "uncomp_size", "method",
                 "strength", "date_time", "crc")

    def __repr__(self):
        return f"<Member {self.name!r} {self.uncomp_size}B AES-{_KEY_LEN[self.strength] * 8}>"


def _parse_extra(extra):
    """Return (strength, real_method) from the 0x9901 AES extra field."""
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == 0x9901 and size >= 7:
            _ver, _vendor, strength, method = struct.unpack("<HHBH", body[:7])
            return strength, method
        i += 4 + size
    return None, None


class AESZipReader:
    """Read a WinZip-AES archive from the central directory."""

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.raw = fh.read()
        self.members = self._read_central_directory()

    def _read_central_directory(self):
        end = self.raw.rfind(_EOCD)
        if end < 0:
            raise ValueError("not a zip file (no end-of-central-directory)")
        count, _size, cd_off = struct.unpack_from("<HII", self.raw, end + 10)
        members, pos = [], cd_off
        for _ in range(count):
            if self.raw[pos:pos + 4] != _CEN:
                raise ValueError(f"bad central directory entry at {pos}")
            (_v1, _v2, _flag, method, mtime, mdate, crc, csize, usize,
             nlen, elen, clen, _disk, _ia, _ea, lho) = struct.unpack_from(
                "<HHHHHHIIIHHHHHII", self.raw, pos + 4)
            name = self.raw[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
            extra = self.raw[pos + 46 + nlen:pos + 46 + nlen + elen]

            m = Member()
            m.name, m.comp_size, m.uncomp_size, m.crc = name, csize, usize, crc
            m.date_time = (
                ((mdate >> 9) & 0x7F) + 1980, (mdate >> 5) & 0x0F, mdate & 0x1F,
                (mtime >> 11) & 0x1F, (mtime >> 5) & 0x3F, (mtime & 0x1F) * 2)
            if method == 99:
                m.strength, m.method = _parse_extra(extra)
            else:
                m.strength, m.method = None, method
            m.offset = lho
            members.append(m)
            pos += 46 + nlen + elen + clen
        return members

    def _payload(self, m):
        """Slice the member's data out, skipping its local file header."""
        nlen, elen = struct.unpack_from("<HH", self.raw, m.offset + 26)
        start = m.offset + 30 + nlen + elen
        return self.raw[start:start + m.comp_size]

    def read(self, m, password, check_hmac=True):
        if m.strength is None:                       # unencrypted member
            blob = self._payload(m)
            return zlib.decompress(blob, -15) if m.method == 8 else blob

        salt_len, key_len = _SALT_LEN[m.strength], _KEY_LEN[m.strength]
        blob = self._payload(m)
        salt, pv = blob[:salt_len], blob[salt_len:salt_len + 2]
        body, auth = blob[salt_len + 2:-10], blob[-10:]

        material = hashlib.pbkdf2_hmac("sha1", password, salt, 1000,
                                       2 * key_len + 2)
        key_aes = material[:key_len]
        key_mac = material[key_len:2 * key_len]
        if material[2 * key_len:] != pv:
            raise ValueError(f"wrong password for {m.name!r} "
                             "(verifier mismatch)")
        if check_hmac:
            mac = hmac.new(key_mac, body, hashlib.sha1).digest()[:10]
            if not hmac.compare_digest(mac, auth):
                raise ValueError(f"authentication failed for {m.name!r}")

        plain = aes_ctr_winzip(key_aes, body)
        return zlib.decompress(plain, -15) if m.method == 8 else plain
