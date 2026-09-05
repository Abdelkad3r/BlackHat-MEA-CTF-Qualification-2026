<?php
$nonce = bin2hex(random_bytes(16));
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; img-src 'self'; base-uri 'none';");

$DOCS = [
  "welcome"  => "Welcome to Lumen, the read-only document relay.",
  "changelog"=> "v3.2 - tightened the content security policy on every view.",
  "contact"  => "Reach the operator through the report console.",
];

function clean($s) {
  if (!is_string($s)) return false;
  if (preg_match('/%3c/i', $s)) return false;
  return htmlspecialchars($s, ENT_QUOTES);
}

$p = isset($_GET['p']) ? $_GET['p'] : 'home';
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lumen</title>
<style nonce="<?=$nonce?>">
  :root{color-scheme:dark}
  body{font-family:ui-monospace,Menlo,monospace;background:#0b0e13;color:#cdd6e6;margin:0}
  header{display:flex;gap:18px;align-items:center;padding:14px 22px;border-bottom:1px solid #1d2533;background:#0e1320}
  header b{color:#7dd3fc;letter-spacing:.04em}
  header a{color:#9fb0c8;text-decoration:none;font-size:14px}
  header a:hover{color:#fff}
  main{max-width:760px;margin:36px auto;padding:0 18px}
  h1{font-size:20px;color:#e7eefc}
  .card{background:#0e1320;border:1px solid #1d2533;border-radius:10px;padding:18px;margin:16px 0}
  input,button{font:inherit;background:#0b0e13;color:#cdd6e6;border:1px solid #2a3445;border-radius:7px;padding:8px 10px}
  button{background:#13283f;color:#7dd3fc;cursor:pointer}
  .err{color:#ff8d8d}
  .muted{color:#6b7a90;font-size:13px}
  label{display:block;margin:8px 0 3px;font-size:13px;color:#9fb0c8}
</style>
</head>
<body>
<header>
  <b>LUMEN</b>
  <a href="?p=home">home</a>
  <a href="?p=report">report</a>
</header>
<main>
<?php if ($p === "home"): ?>
  <h1>Document relay</h1>
  <div class="card">
    <p class="muted">Fetch a published document by folder and name.</p>
    <form action="" method="get">
      <input type="hidden" name="p" value="view">
      <label>folder</label><input name="dir" value="docs/" size="20">
      <label>name</label><input name="file" value="welcome" size="20">
      <p><button type="submit">open</button></p>
    </form>
    <p class="muted">Published: <?= implode(", ", array_keys($DOCS)) ?></p>
  </div>
<?php elseif ($p === "view"):
  $dir = clean(isset($_GET['dir']) ? $_GET['dir'] : "");
  $file = clean(isset($_GET['file']) ? $_GET['file'] : "");
  if ($dir === false || $file === false) {
    echo '<div class="card"><p class="err">Encoded path segments are not allowed.</p></div>';
  } else {
    $path = urldecode($dir . $file);
    $key = preg_replace('#^docs/#', '', $path);
    if (isset($DOCS[$key])) {
      echo '<div class="card"><h1>'.htmlspecialchars($key).'</h1><p>'.htmlspecialchars($DOCS[$key]).'</p></div>';
    } else {
      echo '<div class="card"><p class="err">404 - no document at <b>'.$path.'</b></p>'.
           '<p class="muted">Check the name and try again.</p></div>';
    }
  }
?>
<?php elseif ($p === "report"): ?>
  <h1>Report to operator</h1>
  <div class="card">
    <p class="muted">Submit a Lumen URL and the operator will open it.</p>
    <form action="?p=report" method="post">
      <label>url</label><input name="url" size="48" placeholder="http://127.0.0.1:5000/?p=view&...">
      <p><button type="submit">send to operator</button></p>
    </form>
<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
      $u = (string)$_POST['url'];
      if (preg_match('#^https?://#i', $u) && !preg_match('/[\x00-\x1f]/', $u)) {
        $q = getenv('QUEUE_FILE') ?: '/tmp/lumen/queue';
        @mkdir(dirname($q), 0777, true);
        file_put_contents($q, $u."\n", FILE_APPEND | LOCK_EX);
        echo '<p class="muted">Queued. The operator opens reports shortly.</p>';
      } else {
        echo '<p class="err">Only http(s) URLs are accepted.</p>';
      }
    }
?>
  </div>
<?php elseif ($p === "trace"):
    $id = isset($_GET['id']) ? $_GET['id'] : "";
    if (preg_match('/^[A-Za-z0-9]{8,64}$/', $id)) {
      $d = getenv('TRACE_DIR') ?: '/tmp/lumen/trace';
      $t = $d . '/' . $id;
      if (isset($_GET['note'])) {
        @mkdir($d, 0777, true);
        if (is_file($t) || count(glob($d . '/*') ?: []) < 512) {
          file_put_contents($t, substr((string)$_GET['note'], 0, 1024), LOCK_EX);
        }
      } elseif (is_file($t)) {
        echo '<div class="card"><h1>delivery trace</h1><pre>'.htmlspecialchars((string)file_get_contents($t)).'</pre></div>';
      }
    }
?>
<?php else: ?>
  <div class="card"><p class="err">Unknown page.</p></div>
<?php endif; ?>
</main>
</body>
</html>
