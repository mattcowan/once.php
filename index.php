<?php
// Single-controller private note app
// - Stores notes as JSON data files (non-executable)
// - Prompts for passcode when viewing
// - Enforces a single view, then deletes

// Load .env file if present
$envFile = __DIR__ . DIRECTORY_SEPARATOR . '.env';
if (is_file($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (strpos($line, '=') === false) continue;
        putenv($line);
    }
}

// Configuration
$canonicalHost = getenv('CANONICAL_HOST') ?: '';
$directory = 'private-notes';
$ttlSeconds = 72 * 3600; // 72 hours TTL
$maxNotes = 10000; // Maximum number of notes allowed on disk
$maxPasscodeAttempts = 10; // Lock note after this many failed attempts
$lockoutSeconds = 3600; // 1-hour lockout after max failed attempts
$maxContentBytes = 102400; // 100 KB max note content size
$maxPasscodeBytes = 128; // Hard cap on passcode input length
$keyRotationSeconds = 86400; // Rotate encryption key every 24 hours

// Helpers
function generateCspNonce(): string {
    $GLOBALS['_csp_nonce'] = base64_encode(random_bytes(16));
    return $GLOBALS['_csp_nonce'];
}

function cspNonce(): string {
    return $GLOBALS['_csp_nonce'] ?? '';
}

function securityHeaders(): void {
    $nonce = generateCspNonce();
    header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
}

function ensureNotesDir(string $dir): void {
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
}

function generateRandomPasscode(int $length = 6): string {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $pass = '';
    for ($i = 0; $i < $length; $i++) {
        $idx = random_int(0, $charactersLength - 1);
        $pass .= $characters[$idx];
    }
    return $pass;
}

function generateNoteId(): string {
    return bin2hex(random_bytes(16)); // 32-char hex id
}

function isValidNoteId(string $id): bool {
    return preg_match('/^[0-9a-f]{32}$/', $id) === 1;
}

function notePath(string $dir, string $id): string {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'note_' . $id . '.json';
}

function keyringPath(string $dir): string {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.keyring';
}

function decodeKeyValue(string $val): ?string {
    $val = trim($val);
    if ($val === '') return null;
    $b64 = base64_decode($val, true);
    if ($b64 !== false && strlen($b64) === 32) return $b64;
    if (ctype_xdigit($val) && strlen($val) === 64) {
        $bin = @hex2bin($val);
        if ($bin !== false && strlen($bin) === 32) return $bin;
    }
    if (strlen($val) === 32) return $val;
    return null;
}

/**
 * Read the keyring under an exclusive lock, rotate if the active key is stale,
 * and return the full ring plus the active key entry.
 */
function loadKeyring(string $dir, int $rotationSeconds): array {
    $path = keyringPath($dir);

    // Migrate from legacy .secretkey if it exists
    $legacyPath = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.secretkey';
    if (is_file($legacyPath) && !is_file($path)) {
        $contents = @file_get_contents($legacyPath);
        $decoded = $contents !== false ? decodeKeyValue($contents) : null;
        if ($decoded !== null) {
            $ring = [[
                'id' => bin2hex(random_bytes(8)),
                'key' => base64_encode($decoded),
                'created_at' => time(),
            ]];
            $written = file_put_contents($path, json_encode($ring), LOCK_EX);
            if ($written !== false) {
                @chmod($path, 0600);
                @unlink($legacyPath);
            } else {
                error_log('send-private-note: failed to write .keyring during migration, keeping .secretkey');
            }
        }
    }

    // Open or create the keyring file under exclusive lock
    $fp = @fopen($path, 'c+');
    if ($fp === false) {
        throw new RuntimeException('Cannot open keyring file.');
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        throw new RuntimeException('Cannot lock keyring file.');
    }
    rewind($fp);
    $raw = stream_get_contents($fp);
    $ring = ($raw !== '' && $raw !== false) ? json_decode($raw, true) : null;
    if (!is_array($ring)) {
        $ring = [];
    }

    // Check for env var override — always treated as the active key
    $env = getenv('PRIVATE_NOTES_KEY');
    if ($env !== false && $env !== '') {
        $decoded = decodeKeyValue($env);
        if ($decoded !== null) {
            // Find or create an entry for the env key
            $envB64 = base64_encode($decoded);
            $matchedEntry = null;
            foreach ($ring as $entry) {
                if (!is_array($entry) || !isset($entry['key']) || !is_string($entry['key'])) {
                    continue;
                }
                $entryDecoded = base64_decode($entry['key'], true);
                if ($entryDecoded === false || strlen($entryDecoded) !== 32) {
                    continue;
                }
                if (base64_encode($entryDecoded) === $envB64) {
                    $matchedEntry = $entry;
                    break;
                }
            }
            if ($matchedEntry === null) {
                $matchedEntry = [
                    'id' => bin2hex(random_bytes(8)),
                    'key' => $envB64,
                    'created_at' => time(),
                ];
                $ring[] = $matchedEntry;
                $json = json_encode($ring);
                ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
                @chmod($path, 0600);
            }
            flock($fp, LOCK_UN);
            fclose($fp);
            return ['ring' => $ring, 'active' => $matchedEntry];
        }
    }

    // Auto-rotate: generate a new key if ring is empty or active key is stale
    $now = time();
    $needsRotation = empty($ring);
    if (!$needsRotation) {
        $active = end($ring);
        $needsRotation = ($now - (int)$active['created_at']) >= $rotationSeconds;
    }

    if ($needsRotation) {
        $ring[] = [
            'id' => bin2hex(random_bytes(8)),
            'key' => base64_encode(random_bytes(32)),
            'created_at' => $now,
        ];
        $json = json_encode($ring);
        ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
        @chmod($path, 0600);
    }

    flock($fp, LOCK_UN);
    fclose($fp);
    $active = end($ring);
    return ['ring' => $ring, 'active' => $active];
}

/** Get the active key for encryption. Returns [key_id, raw_key_bytes]. */
function getActiveKey(string $dir, int $rotationSeconds): array {
    $data = loadKeyring($dir, $rotationSeconds);
    $active = $data['active'];
    $key = base64_decode($active['key'] ?? '', true);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Active encryption key is invalid or corrupted.');
    }
    return [$active['id'], $key];
}

/** Look up a specific key by ID for decryption. */
function getKeyById(string $dir, string $keyId, int $rotationSeconds): ?string {
    $data = loadKeyring($dir, $rotationSeconds);
    foreach ($data['ring'] as $entry) {
        if (($entry['id'] ?? '') === $keyId) {
            $key = base64_decode($entry['key'] ?? '', true);
            if ($key === false || strlen($key) !== 32) {
                return null;
            }
            return $key;
        }
    }
    return null;
}

function encryptContent(string $plaintext, string $key): array {
    if (!function_exists('openssl_encrypt')) {
        throw new RuntimeException('OpenSSL extension not available for encryption.');
    }
    $iv = random_bytes(12); // GCM standard nonce size
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return [
        'ciphertext' => base64_encode($ciphertext),
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
    ];
}

function decryptContent(array $data, string $key): ?string {
    if (!isset($data['ciphertext'], $data['iv'], $data['tag'])) return null;
    $ct = base64_decode((string)$data['ciphertext'], true);
    $iv = base64_decode((string)$data['iv'], true);
    $tag = base64_decode((string)$data['tag'], true);
    if ($ct === false || $iv === false || $tag === false) return null;
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($pt === false) return null;
    return $pt;
}

function readNote(string $path): ?array {
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return null;
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return null;
    }
    return $data;
}

function saveNote(string $path, array $data): bool {
    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    return file_put_contents($path, $json, LOCK_EX) !== false;
}

function deleteNoteFile(string $path): void {
    if (is_file($path)) {
        @unlink($path);
    }
}

function html($s): string {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function pageStart(string $subtitle = ''): void {
    $title = 'Once' . ($subtitle ? ' — ' . $subtitle : '');
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">';
    echo '<title>' . html($title) . '</title>';
    echo '<style>
/* ── Light theme (default) ── */
:root{
  --bg:#f0f0f3;--bg-card:#fff;
  --text:#1a1a1d;--text-muted:#444449;--text-faint:#5c5c63;
  --border:#b8b8be;--border-light:#d0d0d5;
  --link:#0050b5;--link-hover:#003a85;
  --btn-bg:#0050b5;--btn-hover:#003a85;--btn-text:#fff;
  --btn2-bg:#d5d5da;--btn2-hover:#b8b8be;--btn2-text:#1a1a1d;
  --copy-bg:#1a7f37;--copy-hover:#156d2e;--copy-text:#fff;
  --share-bg:#e6f0ff;--share-border:#8cb8f0;
  --pass-bg:#e8e8ec;--pass-border:#b8b8be;
  --error:#c62828;--success:#1a7f37;
  --focus-ring:rgba(0,80,181,.45);
  --note-bg:#fff;--note-border:#b8b8be;
  --code-bg:#e2e2e7;
  --accent:#0050b5;
  --toggle-bg:#d5d5da;--toggle-fg:#444449;
}

/* ── Dark theme — deep navy ── */
[data-theme="dark"]{
  --bg:#0d1b2a;--bg-card:#152238;
  --text:#e2e4e8;--text-muted:#a8b0bb;--text-faint:#8891a0;
  --border:#2e3f55;--border-light:#253347;
  --link:#6db3f2;--link-hover:#9dcbf7;
  --btn-bg:#1565c0;--btn-hover:#1976d2;--btn-text:#fff;
  --btn2-bg:#253347;--btn2-hover:#2e3f55;--btn2-text:#e2e4e8;
  --copy-bg:#22863a;--copy-hover:#2ea44f;--copy-text:#fff;
  --share-bg:#152d44;--share-border:#2e5580;
  --pass-bg:#1a2940;--pass-border:#2e3f55;
  --error:#f47068;--success:#56d364;
  --focus-ring:rgba(109,179,242,.5);
  --note-bg:#1a2940;--note-border:#2e3f55;
  --code-bg:#1a2940;
  --accent:#6db3f2;
  --toggle-bg:#253347;--toggle-fg:#a8b0bb;
}

/* Auto-detect OS dark preference when no explicit toggle choice */
@media(prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0d1b2a;--bg-card:#152238;
    --text:#e2e4e8;--text-muted:#a8b0bb;--text-faint:#8891a0;
    --border:#2e3f55;--border-light:#253347;
    --link:#6db3f2;--link-hover:#9dcbf7;
    --btn-bg:#1565c0;--btn-hover:#1976d2;--btn-text:#fff;
    --btn2-bg:#253347;--btn2-hover:#2e3f55;--btn2-text:#e2e4e8;
    --copy-bg:#22863a;--copy-hover:#2ea44f;--copy-text:#fff;
    --share-bg:#152d44;--share-border:#2e5580;
    --pass-bg:#1a2940;--pass-border:#2e3f55;
    --error:#f47068;--success:#56d364;
    --focus-ring:rgba(109,179,242,.5);
    --note-bg:#1a2940;--note-border:#2e3f55;
    --code-bg:#1a2940;
    --accent:#6db3f2;
    --toggle-bg:#253347;--toggle-fg:#a8b0bb;
  }
}

*,*::before,*::after{box-sizing:border-box}
body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}

/* Skip-to-content link (visible only on keyboard focus) */
.skip-link{position:absolute;top:-100%;left:1rem;background:var(--btn-bg);color:var(--btn-text);padding:.5rem 1rem;border-radius:0 0 8px 8px;z-index:100;font-weight:600;text-decoration:none}
.skip-link:focus{top:0}

.wrap{max-width:640px;margin:0 auto;padding:2rem 1.5rem;position:relative}
.header{text-align:center;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border)}
.header h1{font-size:1.75rem;font-weight:700;margin:0 0 .25rem;letter-spacing:-.02em;color:var(--text)}
.header .tagline{font-size:.95rem;color:var(--text-muted);margin:0}

/* Theme toggle */
.theme-toggle{position:absolute;top:1rem;right:1rem;background:var(--toggle-bg);border:1px solid var(--border);color:var(--toggle-fg);border-radius:8px;padding:.4rem .75rem;cursor:pointer;font-size:.8rem;font-weight:600;line-height:1.4;transition:background .15s,color .15s}
.theme-toggle:hover{background:var(--border);color:var(--text)}
.theme-toggle:focus-visible{outline:3px solid var(--focus-ring);outline-offset:2px}

.card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}
h2{font-size:1.2rem;margin:0 0 1rem;font-weight:600;color:var(--text)}
label{font-size:.9rem;font-weight:500;color:var(--text)}
textarea{width:100%;padding:.75rem;border:1px solid var(--border);border-radius:8px;font-size:.95rem;font-family:inherit;resize:vertical;margin-top:.35rem;background:var(--bg-card);color:var(--text)}
textarea:focus-visible,input[type="text"]:focus-visible,input[type="password"]:focus-visible{outline:3px solid var(--focus-ring);outline-offset:1px;border-color:var(--accent)}
input[type="text"],input[type="password"]{padding:.5rem .75rem;border:1px solid var(--border);border-radius:8px;font-size:.95rem;font-family:inherit;background:var(--bg-card);color:var(--text)}
button,.btn{display:inline-block;padding:.6rem 1.25rem;background:var(--btn-bg);color:var(--btn-text);border:none;border-radius:8px;font-size:.95rem;font-weight:600;cursor:pointer;text-decoration:none;transition:background .15s}
button:hover,.btn:hover{background:var(--btn-hover)}
button:focus-visible,.btn:focus-visible{outline:3px solid var(--focus-ring);outline-offset:2px}
.btn-secondary{background:var(--btn2-bg);color:var(--btn2-text)}
.btn-secondary:hover{background:var(--btn2-hover)}
.btn-copy{background:var(--copy-bg);color:var(--copy-text);margin-left:.5rem}
.btn-copy:hover{background:var(--copy-hover)}
.checkbox-label{display:flex;align-items:center;gap:.5rem;margin:.75rem 0;font-size:.9rem;cursor:pointer;color:var(--text)}
.checkbox-label input[type="checkbox"]{width:1.1rem;height:1.1rem;accent-color:var(--accent)}
.share-box{background:var(--share-bg);border:1px solid var(--share-border);border-radius:8px;padding:1rem;margin:.75rem 0;word-break:break-all;font-size:.9rem}
.share-box a{color:var(--link);text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:2px}
.share-box a:hover{color:var(--link-hover)}
.passcode-display{display:inline-block;background:var(--pass-bg);border:1px solid var(--pass-border);border-radius:6px;padding:.3rem .75rem;font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:1.1rem;letter-spacing:.1em;font-weight:600;color:var(--text)}
.error{color:var(--error);font-weight:600}
.consumed{font-style:italic;color:var(--text-muted);margin-top:1rem}
.note-content{background:var(--note-bg);border:1px solid var(--note-border);border-radius:8px;padding:1rem;white-space:pre-wrap;font-size:.95rem;line-height:1.7;color:var(--text)}
.info-section{margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}
.info-section h3{font-size:1rem;font-weight:600;margin:0 0 .5rem;color:var(--text)}
.info-section p,.info-section ul{font-size:.875rem;color:var(--text-muted);margin:.4rem 0;line-height:1.6}
.info-section ul{padding-left:1.25rem}
.info-section li{margin-bottom:.3rem}
.info-section code{background:var(--code-bg);border:1px solid var(--border-light);border-radius:4px;padding:.1rem .35rem;font-size:.85rem;color:var(--text)}
.copy-feedback{display:none;font-size:.85rem;color:var(--success);margin-left:.5rem;font-weight:600}
.form-row{margin-bottom:1rem}
.actions{margin-top:1.25rem}
a{color:var(--link)}
a:hover{color:var(--link-hover)}
    </style>';
    echo '</head><body>';
    echo '<a href="#main" class="skip-link">Skip to main content</a>';
    echo '<div class="wrap">';
    echo '<button type="button" class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode" title="Toggle dark mode"></button>';
    echo '<div id="main" role="main">';
    $rootUrl = html($_SERVER['SCRIPT_NAME'] ?? '/');
    echo '<div class="header"><h1><a href="' . $rootUrl . '" style="color:inherit;text-decoration:none">Once</a></h1><p class="tagline">Here for a moment, then gone for good.</p></div>';
}

function pageEnd(): void {
    echo '</div>'; // close #main
    echo '<script>
(function(){
  var html=document.documentElement,btn=document.getElementById("themeToggle");
  if(!btn) return;
  function getEffective(){
    var s=localStorage.getItem("once-theme");
    if(s==="dark"||s==="light") return s;
    return window.matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light";
  }
  function apply(t){
    html.setAttribute("data-theme",t);
    btn.textContent=t==="dark"?"Light mode":"Dark mode";
    btn.setAttribute("aria-label",t==="dark"?"Switch to light mode":"Switch to dark mode");
  }
  apply(getEffective());
  btn.addEventListener("click",function(){
    var next=getEffective()==="dark"?"light":"dark";
    localStorage.setItem("once-theme",next);
    apply(next);
  });
  window.matchMedia("(prefers-color-scheme:dark)").addEventListener("change",function(){
    if(!localStorage.getItem("once-theme")) apply(getEffective());
  });
})();
</script>';
    echo '</div></body></html>'; // close .wrap
}

function copyScript(): string {
    return '<script>
function copyToClipboard(text, feedbackId) {
  navigator.clipboard.writeText(text).then(function(){
    var el = document.getElementById(feedbackId);
    if(el){el.style.display="inline";setTimeout(function(){el.style.display="none"},2000)}
  }).catch(function(){
    var t=document.createElement("textarea");t.value=text;t.style.position="fixed";t.style.opacity="0";
    document.body.appendChild(t);t.select();document.execCommand("copy");document.body.removeChild(t);
    var el=document.getElementById(feedbackId);
    if(el){el.style.display="inline";setTimeout(function(){el.style.display="none"},2000)}
  });
}
</script>';
}

// Pre-computed dummy hash for timing-safe responses when note is not found
// This ensures password_verify() runs even for missing notes, preventing timing side-channels.
$GLOBALS['_dummy_passcode_hash'] = '$argon2id$v=19$m=65536,t=4,p=1$dW5rbm93bg$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function dummyPasswordVerify(string $input): void {
    password_verify($input, $GLOBALS['_dummy_passcode_hash']);
}

function csrfToken(): string {
    if (session_status() === PHP_SESSION_NONE) {
        session_start(['cookie_samesite' => 'Strict', 'cookie_httponly' => true]);
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrfField(): string {
    return '<input type="hidden" name="csrf_token" value="' . html(csrfToken()) . '">';
}

function verifyCsrf(): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start(['cookie_samesite' => 'Strict', 'cookie_httponly' => true]);
    }
    $token = $_POST['csrf_token'] ?? '';
    return !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function noCacheHeaders(): void {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

// Router
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$noteId = isset($_GET['note']) ? (string)$_GET['note'] : '';

securityHeaders();
if (session_status() === PHP_SESSION_NONE) {
    session_start(['cookie_samesite' => 'Strict', 'cookie_httponly' => true]);
}
ensureNotesDir($directory);

// Validate note ID early — must be exactly 32 hex chars or empty
if ($noteId !== '' && !isValidNoteId($noteId)) {
    echo '<p>Invalid note ID.</p>';
    exit;
}

// Handle note creation
if ($method === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create') {
    if (!verifyCsrf()) {
        pageStart('Error');
        echo '<div class="card"><p>Invalid request. Please reload the page and try again.</p></div>';
        pageEnd();
        exit;
    }
    $content = isset($_POST['content']) ? (string)$_POST['content'] : '';
    $passcode = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';
    $isE2E = isset($_POST['e2e']) && $_POST['e2e'] === '1';
    $e2eRequested = isset($_POST['e2e_requested']) && $_POST['e2e_requested'] === '1';

    // Reject if E2E was requested but JS didn't inject the ciphertext (e.g. JS disabled)
    if ($e2eRequested && !$isE2E) {
        pageStart('Error');
        echo '<div class="card"><p>End-to-end encryption was selected but your browser did not encrypt the note. Please enable JavaScript or uncheck the E2E option.</p></div>';
        pageEnd();
        exit;
    }

    if (!$isE2E && trim($content) === '') {
        echo '<p>Please provide some content for the note.</p>';
    } elseif (!$isE2E && strlen($content) > $maxContentBytes) {
        echo '<p>Note content exceeds the maximum allowed size of ' . ($maxContentBytes / 1024) . ' KB.</p>';
    } else {
        if ($passcode === '') {
            $passcode = generateRandomPasscode(6);
        }
        if (strlen($passcode) !== 6 || !ctype_alnum($passcode)) {
            pageStart('Error');
            echo '<div class="card"><p>Passcode must be exactly 6 alphanumeric characters.</p></div>';
            pageEnd();
            exit;
        } else {
            // Check note count limit
            $existingNotes = glob($directory . DIRECTORY_SEPARATOR . 'note_*.json') ?: [];
            if (count($existingNotes) >= $maxNotes) {
                pageStart('Error');
                echo '<div class="card"><p>The service is at capacity. Please try again later.</p></div>';
                pageEnd();
                exit;
            }
            // Create note id and persist JSON
            do {
                $id = generateNoteId();
                $path = notePath($directory, $id);
            } while (file_exists($path));

            if ($isE2E) {
                $ct = isset($_POST['ciphertext']) ? (string)$_POST['ciphertext'] : '';
                $iv = isset($_POST['iv']) ? (string)$_POST['iv'] : '';
                $tag = isset($_POST['tag']) ? (string)$_POST['tag'] : '';
                if ($ct === '' || $iv === '' || $tag === '') {
                    pageStart('Error');
                    echo '<div class="card"><p>Missing encrypted payload from the browser. Please try again.</p></div>';
                    pageEnd();
                    exit;
                }
                if (strlen($ct) > $maxContentBytes * 2) { // base64 expansion ~1.33x, 2x is generous
                    echo '<p>Encrypted payload exceeds the maximum allowed size.</p>';
                    exit;
                }
                $note = [
                    'type' => 'e2e',
                    'ciphertext' => $ct,
                    'iv' => $iv,
                    'tag' => $tag,
                    'passcode_hash' => password_hash($passcode, PASSWORD_DEFAULT),
                    'remaining_views' => 1,
                    'created_at' => time(),
                    'expires_at' => time() + $ttlSeconds
                ];
            } else {
                try {
                    [$keyId, $key] = getActiveKey($directory, $keyRotationSeconds);
                    $bundle = encryptContent($content, $key);
                } catch (Throwable $e) {
                    error_log('send-private-note: encryption failed: ' . $e->getMessage());
                    pageStart('Error');
                    echo '<div class="card"><p>Encryption is not available. Please try again later.</p></div>';
                    pageEnd();
                    exit;
                }

                $note = [
                    'type' => 'server',
                    'key_id' => $keyId,
                    'ciphertext' => $bundle['ciphertext'],
                    'iv' => $bundle['iv'],
                    'tag' => $bundle['tag'],
                    'passcode_hash' => password_hash($passcode, PASSWORD_DEFAULT),
                    'remaining_views' => 1,
                    'created_at' => time(),
                    'expires_at' => time() + $ttlSeconds
                ];
            }

            if (!saveNote($path, $note)) {
                pageStart('Error');
                echo '<div class="card"><p>Failed to create the note. Please try again.</p></div>';
                pageEnd();
                exit;
            } else {
                error_log(sprintf('send-private-note: note created id=%s… type=%s ip=%s', substr($id, 0, 8), $note['type'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                noCacheHeaders();
                if ($canonicalHost !== '') {
                    $baseUrl = rtrim($canonicalHost, '/') . $_SERVER['SCRIPT_NAME'];
                } else {
                    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
                    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
                    $baseUrl = $scheme . '://' . $host . $_SERVER['SCRIPT_NAME'];
                }
                $fullLink = $baseUrl . '?note=' . urlencode($id);
                pageStart('Note Created');
                echo copyScript();
                echo '<div class="card">';
                echo '<h2>Note Created</h2>';
                if ($isE2E) {
                    echo '<p>Share this link. The decryption key is embedded in the URL fragment &mdash; the server never sees it.</p>';
                    echo '<div class="share-box" id="shareLink">Generating link&hellip;</div>';
                    echo '<div style="margin-top:.5rem"><button class="btn btn-copy" id="copyLinkBtn" style="display:none" onclick="copyToClipboard(document.getElementById(\'shareLinkText\').textContent,\'copyFeedback\')">Copy Link</button><span class="copy-feedback" id="copyFeedback" role="status" aria-live="polite">Copied!</span></div>';
                    echo '<script nonce="' . html(cspNonce()) . '">(function(){var base=' . json_encode($fullLink) . ';var h=window.location.hash||"";var key=h.replace(/^#/,"");var full=base+(key?("#"+key):"");var a=document.createElement("a");a.href=full;a.textContent=full;a.rel="noopener";a.target="_blank";a.id="shareLinkText";var c=document.getElementById("shareLink");c.textContent="";c.appendChild(a);document.getElementById("copyLinkBtn").style.display="inline-block";})();</script>';
                } else {
                    echo '<p>Share this link:</p>';
                    echo '<div class="share-box"><a href="' . html($fullLink) . '" id="shareLinkText">' . html($fullLink) . '</a></div>';
                    echo '<div style="margin-top:.5rem"><button class="btn btn-copy" onclick="copyToClipboard(document.getElementById(\'shareLinkText\').textContent,\'copyFeedback\')">Copy Link</button><span class="copy-feedback" id="copyFeedback" role="status" aria-live="polite">Copied!</span></div>';
                }
                echo '<div class="form-row" style="margin-top:1rem"><label>Passcode (share separately):</label><br>';
                echo '<span class="passcode-display">' . html($passcode) . '</span>';
                echo '<button class="btn btn-copy" onclick="copyToClipboard(\'' . html($passcode) . '\',\'copyPassFeedback\')" style="margin-left:.5rem">Copy</button>';
                echo '<span class="copy-feedback" id="copyPassFeedback" role="status" aria-live="polite">Copied!</span></div>';
                echo '<p style="font-size:.85rem;color:var(--text-muted);margin-top:1rem">This note can be viewed once. After viewing, it self-destructs. Expires in 72 hours if unused.</p>';
                echo '</div>';
                echo '<p style="text-align:center;margin-top:1rem"><a href="' . html(basename(__FILE__)) . '" class="btn btn-secondary">Create Another Note</a></p>';
                pageEnd();
                exit;
            }
        }
    }
}

// Handle note viewing (passcode prompt and consume)
if ($noteId !== '') {
    $path = notePath($directory, $noteId);

    // E2E fetch API: returns ciphertext JSON, consumes the note
    if ($method === 'POST' && isset($_POST['action']) && $_POST['action'] === 'fetch') {
        noCacheHeaders();
        header('Content-Type: application/json');
        if (!verifyCsrf()) {
            echo json_encode(['error' => 'invalid_request']); exit;
        }
        $inputPass = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';
        if (strlen($inputPass) > $maxPasscodeBytes) {
            echo json_encode(['error' => 'bad_pass']); exit;
        }
        if (!is_file($path)) {
            dummyPasswordVerify($inputPass);
            echo json_encode(['error' => 'not_found']); exit;
        }
        $fp = @fopen($path, 'r+');
        if ($fp === false) { dummyPasswordVerify($inputPass); echo json_encode(['error' => 'not_found']); exit; }
        if (!flock($fp, LOCK_EX)) { fclose($fp); echo json_encode(['error' => 'lock_failed']); exit; }
        rewind($fp);
        $raw = stream_get_contents($fp);
        $data = $raw ? json_decode($raw, true) : null;
        $now = time();
        if (!is_array($data)) { flock($fp, LOCK_UN); fclose($fp); deleteNoteFile($path); echo json_encode(['error' => 'not_found']); exit; }
        if (isset($data['expires_at']) && $now > (int)$data['expires_at']) { flock($fp, LOCK_UN); fclose($fp); deleteNoteFile($path); echo json_encode(['error' => 'expired']); exit; }
        if (($data['type'] ?? '') !== 'e2e') { flock($fp, LOCK_UN); fclose($fp); echo json_encode(['error' => 'wrong_type']); exit; }
        if ((int)$data['remaining_views'] <= 0) { flock($fp, LOCK_UN); fclose($fp); deleteNoteFile($path); echo json_encode(['error' => 'consumed']); exit; }
        // Rate limiting: check failed attempts
        $failedAttempts = (int)($data['failed_attempts'] ?? 0);
        $lockedUntil = (int)($data['locked_until'] ?? 0);
        if ($failedAttempts >= $maxPasscodeAttempts && $now < $lockedUntil) {
            flock($fp, LOCK_UN); fclose($fp);
            echo json_encode(['error' => 'locked']); exit;
        }
        if (!isset($data['passcode_hash']) || !password_verify($inputPass, $data['passcode_hash'])) {
            $data['failed_attempts'] = $failedAttempts + 1;
            if ($data['failed_attempts'] >= $maxPasscodeAttempts) {
                $data['locked_until'] = $now + $lockoutSeconds;
            }
            $json = json_encode($data, JSON_UNESCAPED_SLASHES);
            ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
            flock($fp, LOCK_UN); fclose($fp);
            error_log(sprintf('send-private-note: bad passcode (e2e) note=%s… attempt=%d ip=%s', substr($noteId, 0, 8), $data['failed_attempts'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            echo json_encode(['error' => 'bad_pass']); exit;
        }
        $payload = ['ciphertext' => $data['ciphertext'], 'iv' => $data['iv'], 'tag' => $data['tag']];
        $data['remaining_views'] = 0;
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
        flock($fp, LOCK_UN); fclose($fp);
        deleteNoteFile($path);
        error_log(sprintf('send-private-note: note consumed (e2e) id=%s… ip=%s', substr($noteId, 0, 8), $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        echo json_encode(['ok' => true, 'data' => $payload]);
        exit;
    }

    // If POST view attempt
    if ($method === 'POST' && isset($_POST['action']) && $_POST['action'] === 'view') {
        if (!verifyCsrf()) {
            pageStart('Error');
            echo '<div class="card"><p>Invalid request. Please reload the page and try again.</p></div>';
            pageEnd();
            exit;
        }
        $inputPass = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';
        if (strlen($inputPass) > $maxPasscodeBytes) {
            echo '<p style="color:#b00;">Invalid passcode.</p>';
            exit;
        }

        // Atomic verify + decrement under lock
        if (!is_file($path)) {
            dummyPasswordVerify($inputPass);
            pageStart('Not Found');
            echo '<div class="card"><p>This note does not exist or has expired.</p></div>';
            pageEnd();
            exit;
        }
        $fp = @fopen($path, 'r+');
        if ($fp === false) {
            dummyPasswordVerify($inputPass);
            pageStart('Not Found');
            echo '<div class="card"><p>This note does not exist or has expired.</p></div>';
            pageEnd();
            exit;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            pageStart('Error');
            echo '<div class="card"><p>Could not lock the note. Please try again.</p></div>';
            pageEnd();
            exit;
        }
        rewind($fp);
        $raw = stream_get_contents($fp);
        $data = $raw ? json_decode($raw, true) : null;
        $now = time();
        if (!is_array($data) || !isset($data['remaining_views'])) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            pageStart('Not Found');
            echo '<div class="card"><p>This note does not exist or has expired.</p></div>';
            pageEnd();
            exit;
        }
        if (isset($data['expires_at']) && $now > (int)$data['expires_at']) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            pageStart('Expired');
            echo '<div class="card"><p>This note has expired and is no longer available.</p></div>';
            pageEnd();
            exit;
        }
        if (($data['type'] ?? '') !== 'server') {
            flock($fp, LOCK_UN);
            fclose($fp);
            pageStart('Wrong Type');
            echo '<div class="card"><p>This note uses end-to-end encryption. Please refresh and use the in-browser viewer.</p></div>';
            pageEnd();
            exit;
        }
        if ((int)$data['remaining_views'] <= 0) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            pageStart('Gone');
            echo '<div class="card"><p>This note has already been viewed and is no longer available.</p></div>';
            pageEnd();
            exit;
        }
        // Rate limiting: check failed attempts
        $failedAttempts = (int)($data['failed_attempts'] ?? 0);
        $lockedUntil = (int)($data['locked_until'] ?? 0);
        if ($failedAttempts >= $maxPasscodeAttempts && $now < $lockedUntil) {
            flock($fp, LOCK_UN);
            fclose($fp);
            pageStart('Locked');
            echo '<div class="card"><h2>Note Locked</h2>';
            echo '<p class="error" role="alert">Too many failed attempts. Please try again later.</p></div>';
            pageEnd();
            exit;
        }
        if (!isset($data['passcode_hash']) || !password_verify($inputPass, $data['passcode_hash'])) {
            $data['failed_attempts'] = $failedAttempts + 1;
            if ($data['failed_attempts'] >= $maxPasscodeAttempts) {
                $data['locked_until'] = $now + $lockoutSeconds;
            }
            $json = json_encode($data, JSON_UNESCAPED_SLASHES);
            ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
            error_log(sprintf('send-private-note: bad passcode (server) note=%s… attempt=%d ip=%s', substr($noteId, 0, 8), $data['failed_attempts'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            // Re-show prompt with error
            pageStart('Enter Passcode');
            echo '<div class="card">';
            echo '<h2>Enter Passcode</h2>';
            echo '<p class="error" role="alert">Invalid passcode. Please try again.</p>';
            echo '<form method="post">';
            echo csrfField();
            echo '<input type="hidden" name="action" value="view">';
            echo '<div class="form-row"><label for="passcode">Passcode:</label><br><input type="password" id="passcode" name="passcode" placeholder="6-character passcode" required maxlength="128"></div>';
            echo '<div class="actions"><button type="submit">View Note</button></div>';
            echo '</form></div>';
            pageEnd();
            exit;
        }

        // Valid passcode: decrypt and consume the single view
        try {
            $keyId = $data['key_id'] ?? '';
            $key = $keyId !== '' ? getKeyById($directory, $keyId, $keyRotationSeconds) : null;
            // Fallback for notes created before keyring migration
            if ($key === null) {
                [$_, $key] = getActiveKey($directory, $keyRotationSeconds);
            }
            $contentRaw = decryptContent($data, $key);
        } catch (Throwable $e) {
            $contentRaw = null;
        }
        if (!is_string($contentRaw)) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            pageStart('Error');
            echo '<div class="card"><p>Unable to decrypt this note or it has expired.</p></div>';
            pageEnd();
            exit;
        }
        $data['remaining_views'] = max(0, (int)$data['remaining_views'] - 1);
        // Persist updated state
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $json);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        if ((int)$data['remaining_views'] <= 0) {
            deleteNoteFile($path);
        }
        error_log(sprintf('send-private-note: note consumed (server) id=%s… ip=%s', substr($noteId, 0, 8), $_SERVER['REMOTE_ADDR'] ?? 'unknown'));

        // Render the note content once
        noCacheHeaders();
        pageStart('Your Private Note');
        echo '<div class="card">';
        echo '<h2>Your Private Note</h2>';
        echo '<div class="note-content">' . nl2br(html($contentRaw)) . '</div>';
        echo '<p class="consumed">This note has been consumed and cannot be viewed again.</p>';
        echo '</div>';
        pageEnd();
        exit;
    }

    // GET: Inspect note to decide viewer type
    $data = readNote($path);
    $now = time();
    if (!is_array($data)) { pageStart('Not Found'); echo '<div class="card"><p>This note does not exist or has expired.</p></div>'; pageEnd(); exit; }
    if (isset($data['expires_at']) && $now > (int)$data['expires_at']) { deleteNoteFile($path); pageStart('Expired'); echo '<div class="card"><p>This note has expired and is no longer available.</p></div>'; pageEnd(); exit; }
    $type = $data['type'] ?? 'server';
    if ($type === 'e2e') {
        echo '<h3>Enter Passcode</h3>';
        echo '<p>The decryption key must be present in the URL fragment (#...). Only your browser sees it.</p>';
        echo '<div id="keyStatus" style="color:#b00;"></div>';
        echo '<input type="password" id="passcode" placeholder="6-character passcode" maxlength="128"> ';
        echo '<button id="viewBtn">Decrypt & View (consumes note)</button>';
        echo '<pre id="output" style="white-space:pre-wrap; display:none;"></pre>';
        echo '<script nonce="' . html(cspNonce()) . '">
        (function(){
          var csrfToken = ' . json_encode(csrfToken()) . ';
          function b64ToBytes(b64){ return Uint8Array.from(atob(b64), c=>c.charCodeAt(0)); }
          function b64urlToBytes(b64u){ b64u=b64u.replace(/-/g, "+").replace(/_/g, "/"); var pad = b64u.length % 4; if (pad) b64u += "===".slice(pad); return b64ToBytes(b64u); }
          async function decryptGCM(keyBytes, ivBytes, ctBytes, tagBytes){
            const key = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["decrypt"]);
            const ctTag = new Uint8Array(ctBytes.length + tagBytes.length);
            ctTag.set(ctBytes,0); ctTag.set(tagBytes, ctBytes.length);
            const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv: ivBytes}, key, ctTag);
            return new TextDecoder().decode(pt);
          }
          function getKey(){ var h=window.location.hash.replace(/^#/,""); if (!h) return null; if (h.startsWith("key=")) h=h.slice(4); try { return b64urlToBytes(h); } catch(e){ return null; } }
          var key = getKey();
          var keyStatus = document.getElementById("keyStatus");
          if (!key) { keyStatus.textContent = "Missing or invalid decryption key in URL fragment."; }
          document.getElementById("viewBtn").addEventListener("click", async function(){
            if (!key) { alert("Missing key in URL fragment."); return; }
            var pass = document.getElementById("passcode").value || "";
            try {
              const resp = await fetch(window.location.href, { method: "POST", headers: {"Content-Type":"application/x-www-form-urlencoded"}, body: new URLSearchParams({ action: "fetch", passcode: pass, csrf_token: csrfToken }) });
              const j = await resp.json();
              if (!j.ok) { alert(j.error || "Failed"); return; }
              const ct = b64ToBytes(j.data.ciphertext);
              const iv = b64ToBytes(j.data.iv);
              const tag = b64ToBytes(j.data.tag);
              const plaintext = await decryptGCM(key, iv, ct, tag);
              var out = document.getElementById("output");
              out.textContent = plaintext;
              document.getElementById("outputCard").style.display = "block";
              keyStatus.textContent = "";
            } catch (e) {
              alert("Decryption failed: " + e);
            }
          });
        })();
        </script>';
        pageEnd();
        exit;
    }

    // Default server-side decryption prompt
    pageStart('Enter Passcode');
    echo '<div class="card">';
    echo '<h2>Enter Passcode</h2>';
    echo '<form method="post">';
    echo csrfField();
    echo '<input type="hidden" name="action" value="view">';
    echo '<div class="form-row"><label for="passcode">Passcode:</label><br><input type="password" id="passcode" name="passcode" placeholder="6-character passcode" required maxlength="128"></div>';
    echo '<div class="actions"><button type="submit">View Note</button></div>';
    echo '</form></div>';
    pageEnd();
    exit;
}

// Default: show create form
$autoGeneratedPasscode = generateRandomPasscode(6);
pageStart('Create a Note');
echo '<div class="card">';
echo '<h2>Create a Private Note</h2>';
echo '<form id="createForm" method="post" action="' . html($_SERVER['PHP_SELF']) . '">';
echo csrfField();
echo '<input type="hidden" name="action" value="create">';
echo '<div class="form-row"><label for="content">Your message:</label>';
echo '<textarea id="content" name="content" rows="6" required placeholder="Type your private note here..."></textarea></div>';
echo '<div class="form-row"><label for="passcode">Passcode (6 alphanumeric characters):</label><br>';
echo '<input type="text" id="passcode" name="passcode" value="' . html($autoGeneratedPasscode) . '" maxlength="6" required style="margin-top:.35rem;font-family:monospace;letter-spacing:.1em"></div>';
echo '<input type="hidden" name="e2e_requested" value="0">';
echo '<label class="checkbox-label"><input type="checkbox" id="e2e" name="e2e_requested" value="1" checked> End-to-end encryption (E2E)</label>';
echo '<noscript><p class="error">End-to-end encryption requires JavaScript. If JavaScript is disabled, your note will use server-side encryption instead.</p></noscript>';
echo '<div class="actions"><button type="submit">Create Note</button></div>';
echo '</form>';
echo '<script nonce="' . html(cspNonce()) . '">
(function(){
  const form = document.getElementById("createForm");
  const e2e = document.getElementById("e2e");
  function bytesToB64(bytes){ return btoa(String.fromCharCode.apply(null, Array.from(bytes))); }
  function b64url(bytes){ return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
  async function encryptInBrowser(ev){
    if (!e2e.checked) return; // normal flow
    ev.preventDefault();
    
    try {
      const contentEl = document.getElementById("content");
      const content = contentEl.value;
      if (!content) { alert("Please provide some content for the note."); return; }
      
      // Check if Web Crypto API is available
      if (!window.crypto || !window.crypto.subtle) {
        alert("Your browser does not support end-to-end encryption. Please uncheck the E2E option.");
        return;
      }
      
      const te = new TextEncoder();
      const keyBytes = new Uint8Array(32); 
      crypto.getRandomValues(keyBytes);
      const iv = new Uint8Array(12); 
      crypto.getRandomValues(iv);
      
      const key = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["encrypt"]);
      const ctTag = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, te.encode(content));
      const buf = new Uint8Array(ctTag);
      const tagLen = 16; const ctLen = buf.length - tagLen;
      const ct = buf.slice(0, ctLen); const tag = buf.slice(ctLen);
      
      // Prepare hidden inputs
      const setHidden = (name, val)=>{ let i=document.createElement("input"); i.type="hidden"; i.name=name; i.value=val; form.appendChild(i); };
      setHidden("e2e", "1");
      setHidden("ciphertext", bytesToB64(ct));
      setHidden("iv", bytesToB64(iv));
      setHidden("tag", bytesToB64(tag));
      
      // Remove plaintext content to avoid sending it
      contentEl.disabled = true;
      
      // Carry key via URL fragment so server never sees it
      const actionUrl = form.getAttribute("action") || window.location.href || "";
      const base = String(actionUrl).split("#")[0];
      form.setAttribute("action", base + "#key=" + b64url(keyBytes));
      form.submit();
    } catch (error) {
      console.error("E2E encryption failed:", error);
      alert("Encryption failed: " + error.message + ". Please try again or uncheck the E2E option.");
    }
  }
  form.addEventListener("submit", encryptInBrowser);
})();
</script>';
pageEnd();
?>
