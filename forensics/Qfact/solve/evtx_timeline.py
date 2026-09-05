#!/usr/bin/env python3
"""Keyword timeline across .evtx files without a full binary-XML parser.

EVTX records begin with the magic 2A 2A 00 00 followed by size, record number
and a FILETIME. That is enough to timestamp a record; the printable UTF-16
runs inside it carry the rendered EventData. Good enough for triage, and it
avoids a dependency on python-evtx.

Usage:
    python3 evtx_timeline.py <file.evtx | dir> [keyword ...]
"""
import argparse
import datetime
import pathlib
import re
import struct
import sys

RECORD_MAGIC = b"\x2a\x2a\x00\x00"
# Guard against false-positive magics: only accept plausible 2000-2100 FILETIMEs.
FT_MIN, FT_MAX = 125911584000000000, 158000000000000000
UTF16_RUN = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")


def records(path):
    data = path.read_bytes()
    off = 0
    while True:
        i = data.find(RECORD_MAGIC, off)
        if i < 0:
            return
        off = i + 4
        try:
            size, num, ft = struct.unpack_from("<IQQ", data, i + 4)
        except struct.error:
            continue
        if not 0x30 <= size <= 0x100000 or i + size > len(data):
            continue
        if not FT_MIN < ft < FT_MAX:
            continue
        ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        yield ts, num, data[i:i + size]


def strings(body):
    return [m.group().decode("utf-16-le") for m in UTF16_RUN.finditer(body)]


def event_ids(body, candidates):
    return [e for e in candidates if struct.pack("<H", e) in body]


COMMON_IDS = (1000, 1001, 1116, 1117, 5007, 4104, 4103, 4688, 4689, 4624, 4625)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", type=pathlib.Path)
    ap.add_argument("keywords", nargs="*", help="case-insensitive substrings")
    ap.add_argument("-w", "--width", type=int, default=400)
    args = ap.parse_args()

    files = sorted(args.target.rglob("*.evtx")) if args.target.is_dir() else [args.target]
    kws = [k.lower() for k in args.keywords]

    rows = []
    for f in files:
        for ts, num, body in records(f):
            ss = [s for s in strings(body) if len(s) > 3]
            if kws and not any(k in " | ".join(ss).lower() for k in kws):
                continue
            text = " | ".join(s.replace("\r", "").replace("\n", " ") for s in ss)
            rows.append((ts, f.name, num, event_ids(body, COMMON_IDS), text))

    seen = set()
    for ts, fname, num, eids, text in sorted(rows):
        if (fname, num) in seen:
            continue
        seen.add((fname, num))
        eid = ",".join(str(e) for e in eids) or "?"
        print(f"[{ts}] {fname} #{num} (EID {eid})")
        print(f"    {text[:args.width]}")
    if not rows:
        print("no matching records", file=sys.stderr)


if __name__ == "__main__":
    main()
