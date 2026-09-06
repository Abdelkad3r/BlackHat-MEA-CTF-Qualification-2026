#!/usr/bin/env python3
"""Recover a plaintext from a raw-RSA population-count oracle.

The service lets us obtain ``HW(r * m mod n)`` for chosen r. We use streams
for r*2**i and their negatives. For a value a, doubling preserves HW exactly
when a < n/2. Doubling n-a preserves HW exactly when a >= n/2. Hence the pair
classifies a binary digit of a/n, except for a rare popcount collision.

Independent streams for small odd r (3, 5, 7, ...) resolve those erasures.
The network client is in exploit.py.
"""

from __future__ import annotations

import argparse
import secrets
import sys


# The search advances one binary digit per recursive frame. RSA-2048 therefore
# needs a modestly larger recursion allowance than Python's default 1000.
sys.setrecursionlimit(10_000)


def ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def classify(positive: list[int], negative: list[int]) -> list[int | None]:
    """Classify each a_i as lower/upper half of Z_n, or an erasure."""
    if len(positive) != len(negative):
        raise ValueError("Mismatched stream lengths.")
    result: list[int | None] = []
    for before, after, opposite_before, opposite_after in zip(
        positive, positive[1:], negative, negative[1:]
    ):
        if before != after:
            result.append(1)
        elif opposite_before != opposite_after:
            result.append(0)
        else:
            result.append(None)
    return result


def determined_half(prefix: int, known_bits: int, shift: int, multiplier: int) -> int | None:
    """Return MSB(frac(multiplier * 2**shift * m/n)) if prefix fixes it."""
    remaining = known_bits - shift
    if remaining <= 0:
        return None
    denominator = 1 << remaining
    if denominator <= 2 * multiplier:
        return None
    residue = prefix & (denominator - 1)
    lower = multiplier * residue
    upper = lower + multiplier - 1
    lower_bucket = (2 * lower) // denominator
    upper_bucket = (2 * upper) // denominator
    if lower_bucket != upper_bucket:
        return None
    return lower_bucket & 1


def recover_labels(
    modulus: int,
    labels: dict[int, list[int | None]],
    primary_weights: list[int],
    *,
    verbose: bool = False,
) -> int:
    """Recover m from exact half-bit labels, permitting erased secondary labels."""
    if 1 not in labels:
        raise ValueError("The unblinded multiplier-1 stream is required.")
    target_bits = modulus.bit_length()
    if len(labels[1]) < target_bits:
        raise ValueError("Collect at least bit_length(n)+1 values for multiplier 1.")

    erasures = sum(value is None for value in labels[1][:target_bits])
    if verbose:
        print(f"[*] primary erasures: {erasures}; multipliers: {sorted(labels)}")

    nodes = 0

    def compatible(prefix: int, depth: int) -> bool:
        # Each label at shift i concerns frac(r * 2**i * m/n). Once the
        # prefix makes it definite, it becomes an exact constraint.
        for multiplier, values in labels.items():
            for shift in range(min(depth, len(values))):
                expected = values[shift]
                if expected is None:
                    continue
                actual = determined_half(prefix, depth, shift, multiplier)
                if actual is not None and actual != expected:
                    return False
        return True

    def visit(prefix: int, depth: int) -> int | None:
        nonlocal nodes
        nodes += 1
        if not compatible(prefix, depth):
            return None
        if depth == target_bits:
            low = ceil_div(modulus * prefix, 1 << depth)
            high = ceil_div(modulus * (prefix + 1), 1 << depth) - 1
            if low != high or low >= modulus:
                return None
            value = low
            for expected in primary_weights:
                if value.bit_count() != expected:
                    return None
                value = (value << 1) % modulus
            return low

        label = labels[1][depth]
        choices = (label,) if label is not None else (0, 1)
        for bit in choices:
            result = visit((prefix << 1) | bit, depth + 1)
            if result is not None:
                return result
        return None

    result = visit(0, 0)
    if verbose:
        print(f"[*] explored {nodes} prefix nodes")
    if result is None:
        raise ValueError("No plaintext survived; collect more multiplier streams.")
    return result


def recover(modulus: int, stream_weights: dict[int, tuple[list[int], list[int]]], *, verbose: bool = False) -> int:
    """Recover m from complete {multiplier: (HW(+stream), HW(-stream))} streams."""
    labels = {r: classify(*weights) for r, weights in stream_weights.items()}
    return recover_labels(modulus, labels, stream_weights[1][0], verbose=verbose)


def demo(bits: int, multipliers: list[int]) -> None:
    modulus = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    message = secrets.randbelow(modulus - 1) + 1
    streams: dict[int, tuple[list[int], list[int]]] = {}
    for multiplier in multipliers:
        value = (multiplier * message) % modulus
        positive, negative = [], []
        for _ in range(bits + 6):
            positive.append(value.bit_count())
            negative.append((modulus - value).bit_count())
            value = (value << 1) % modulus
        streams[multiplier] = positive, negative
    candidate = recover(modulus, streams, verbose=True)
    print(f"expected = {message}")
    print(f"recovered = {candidate}")
    print(f"success = {candidate == message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", type=int, metavar="BITS")
    parser.add_argument("--multipliers", default="1,3,5,7,11")
    args = parser.parse_args()
    if args.demo:
        demo(args.demo, [int(value) for value in args.multipliers.split(",")])
    else:
        parser.error("Use --demo BITS, or import recover() from exploit.py.")


if __name__ == "__main__":
    main()
