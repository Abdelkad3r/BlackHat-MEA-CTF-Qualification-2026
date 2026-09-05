#!/usr/bin/env python3
"""Recover a quarantined sample and its metadata from a Microsoft Defender
Quarantine folder.

Defender obfuscates every file under \\ProgramData\\Microsoft\\Windows Defender\\
Quarantine\\ with RC4 under a static 256-byte key that ships inside mpengine.dll.
Two container formats sit on top of that:

  Entries\\{GUID}          three *independent* RC4 streams laid end to end
                           (header 0x3C, then two sections whose lengths the
                           header carries at +0x28 and +0x2C)
  ResourceData\\XX\\<SHA1>  one RC4 stream wrapping a security descriptor and
                           one or more NTFS streams; stream 0 is the original file

Usage:
    python3 extract_quarantine.py <Quarantine dir> [-o outdir]
"""
import argparse
import datetime
import hashlib
import pathlib
import re
import struct
import sys

# Static RC4 key extracted from mpengine.dll; unchanged for many years.
RC4_KEY = bytes([
    0x1E,0x87,0x78,0x1B,0x8D,0xBA,0xA8,0x44,0xCE,0x69,0x70,0x2C,0x0C,0x78,0xB7,0x86,
    0xA3,0xF6,0x23,0xB7,0x38,0xF5,0xED,0xF9,0xAF,0x83,0x53,0x0F,0xB3,0xFC,0x54,0xFA,
    0xA2,0x1E,0xB9,0xCF,0x13,0x31,0xFD,0x0F,0x0D,0xA9,0x54,0xF6,0x87,0xCB,0x9E,0x18,
    0x27,0x96,0x97,0x90,0x0E,0x53,0xFB,0x31,0x7C,0x9C,0xBC,0xE4,0x8E,0x23,0xD0,0x53,
    0x71,0xEC,0xC1,0x59,0x51,0xB8,0xF3,0x64,0x9D,0x7C,0xA3,0x3E,0xD6,0x8D,0xC9,0x04,
    0x7E,0x82,0xC9,0xBA,0xAD,0x97,0x99,0xD0,0xD4,0x58,0xCB,0x84,0x7C,0xA9,0xFF,0xBE,
    0x3C,0x8A,0x77,0x52,0x33,0x55,0x7D,0xDE,0x13,0xA8,0xB1,0x40,0x87,0xCC,0x1B,0xC8,
    0xF1,0x0F,0x6E,0xCD,0xD0,0x83,0xA9,0x59,0xCF,0xF8,0x4A,0x9D,0x1D,0x50,0x75,0x5E,
    0x3E,0x19,0x18,0x18,0xAF,0x23,0xE2,0x29,0x35,0x58,0x76,0x6D,0x2C,0x07,0xE2,0x57,
    0x12,0xB2,0xCA,0x0B,0x53,0x5E,0xD8,0xF6,0xC5,0x6C,0xE7,0x3D,0x24,0xBD,0xD0,0x29,
    0x17,0x71,0x86,0x1A,0x54,0xB4,0xC2,0x85,0xA9,0xA3,0xDB,0x7A,0xCA,0x6D,0x22,0x4A,
    0xEA,0xCD,0x62,0x1D,0xB9,0xF2,0xA2,0x2E,0xD1,0xE9,0xE1,0x1D,0x75,0xBE,0xD7,0xDC,
    0x0E,0xCB,0x0A,0x8E,0x68,0xA2,0xFF,0x12,0x63,0x40,0x8D,0xC8,0x08,0xDF,0xFD,0x16,
    0x4B,0x11,0x67,0x74,0xCD,0x0B,0x9B,0x8D,0x05,0x41,0x1E,0xD6,0x26,0x2E,0x42,0x9B,
    0xA4,0x95,0x67,0x6B,0x83,0x98,0xDB,0x2F,0x35,0xD3,0xC1,0xB9,0xCE,0xD5,0x26,0x36,
    0xF2,0x76,0x5E,0x1A,0x95,0xCB,0x7C,0xA4,0xC3,0xDD,0xAB,0xDD,0xBF,0xF3,0x82,0x53,
])


def rc4(data, key=RC4_KEY):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def filetime(v):
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)


def utf16_strings(buf, minlen=4):
    pat = ("(?:[\\x20-\\x7e]\\x00){%d,}" % minlen).encode()
    return [m.group().decode("utf-16-le") for m in re.finditer(pat, buf)]


def parse_entry(path):
    """Entries\\{GUID}: header + two sections, each its own RC4 keystream."""
    raw = path.read_bytes()
    header = rc4(raw[:0x3C])
    len1, len2 = struct.unpack_from("<II", header, 0x28)
    body = raw[0x3C:]
    sec1 = rc4(body[:len1])
    sec2 = rc4(body[len1:len1 + len2])

    threat = sec1[0x34:].split(b"\x00")[0].decode("ascii", "replace")
    info = {
        "guid": path.name,
        "threat": threat,
        "quarantined_utc": filetime(struct.unpack_from("<Q", sec1, 0x20)[0]),
        "paths": [p for p in utf16_strings(sec2) if ":\\" in p],
    }
    return info


def parse_resourcedata(path):
    """ResourceData\\XX\\<SHA1>: one RC4 stream; returns (payload, container)."""
    blob = rc4(path.read_bytes())
    sd_len = struct.unpack_from("<I", blob, 0x08)[0]
    off = 0x10 + sd_len
    off += (-off) % 8                       # sections are 8-byte aligned
    _n_streams = struct.unpack_from("<Q", blob, off)[0]
    size = struct.unpack_from("<Q", blob, off + 8)[0]
    data_off = off + 0x14                   # +8 count, +8 size, +4 stream-name len
    return blob[data_off:data_off + size], blob


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("quarantine", type=pathlib.Path,
                    help="path to the Quarantine directory")
    ap.add_argument("-o", "--outdir", type=pathlib.Path, default=pathlib.Path("recovered"),
                    help="where to write recovered samples (default: ./recovered)")
    args = ap.parse_args()

    entries_dir = args.quarantine / "Entries"
    rdata_dir = args.quarantine / "ResourceData"
    if not entries_dir.is_dir():
        sys.exit(f"no Entries directory under {args.quarantine}")

    args.outdir.mkdir(parents=True, exist_ok=True)

    for entry in sorted(entries_dir.iterdir()):
        if not entry.is_file():
            continue
        info = parse_entry(entry)
        print(f"[entry] {info['guid']}")
        print(f"        threat      : {info['threat']}")
        print(f"        quarantined : {info['quarantined_utc']} UTC")
        for p in info["paths"]:
            print(f"        origin      : {p}")

    for res in sorted(rdata_dir.rglob("*")):
        if not res.is_file():
            continue
        payload, container = parse_resourcedata(res)
        # Defender names the file after the SHA1 of the decrypted container.
        ok = hashlib.sha1(container).hexdigest().upper() == res.name.upper()
        out = args.outdir / f"{res.name}.bin"
        out.write_bytes(payload)
        print(f"[data ] {res.name}")
        print(f"        container sha1 matches name : {ok}")
        print(f"        payload size   : {len(payload)}")
        print(f"        payload md5    : {hashlib.md5(payload).hexdigest()}")
        print(f"        payload sha256 : {hashlib.sha256(payload).hexdigest()}")
        print(f"        written to     : {out}")


if __name__ == "__main__":
    main()
