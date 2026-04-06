<?php
// Single-controller private note app
// - Stores notes as JSON data files (non-executable)
// - Prompts for passcode when viewing
// - Enforces a single view, then deletes

// Configuration
$directory = 'private-notes';
$ttlSeconds = 72 * 3600; // 72 hours TTL
$maxNotes = 10000; // Maximum number of notes allowed on disk
$maxPasscodeAttempts = 5; // Lock note after this many failed attempts
$lockoutSeconds = 900; // 15-minute lockout after max failed attempts

// Helpers
function securityHeaders(): void {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
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

function notePath(string $dir, string $id): string {
    $safeId = basename($id);
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'note_' . $safeId . '.json';
}

function secretKeyPath(string $dir): string {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.secretkey';
}

function getServerKey(string $dir): string {
    $env = getenv('PRIVATE_NOTES_KEY');
    $tryDecode = function ($val) {
        if ($val === '' || $val === false || $val === null) return null;
        $val = trim((string)$val);
        $b64 = base64_decode($val, true);
        if ($b64 !== false && strlen($b64) === 32) return $b64;
        if (ctype_xdigit($val) && strlen($val) === 64) {
            $bin = @hex2bin($val);
            if ($bin !== false && strlen($bin) === 32) return $bin;
        }
        if (strlen($val) === 32) return $val; // raw 32 bytes in env (unlikely)
        return null;
    };
    $key = $tryDecode($env);
    if ($key !== null) return $key;

    $keyFile = secretKeyPath($dir);
    if (is_file($keyFile)) {
        $contents = @file_get_contents($keyFile);
        $decoded = $tryDecode($contents);
        if ($decoded !== null) return $decoded;
    }

    // Generate a new key and persist as base64
    $newKey = random_bytes(32);
    $b64 = base64_encode($newKey);
    @file_put_contents($keyFile, $b64, LOCK_EX);
    @chmod($keyFile, 0600);
    return $newKey;
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
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache');
}

// Router
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$noteId = isset($_GET['note']) ? (string)$_GET['note'] : '';

securityHeaders();
ensureNotesDir($directory);

// Handle note creation
if ($method === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create') {
    if (!verifyCsrf()) {
        echo '<p>Invalid request. Please reload the page and try again.</p>';
        exit;
    }
    $content = isset($_POST['content']) ? (string)$_POST['content'] : '';
    $passcode = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';
    $isE2E = isset($_POST['e2e']) && $_POST['e2e'] === '1';

    if (!$isE2E && trim($content) === '') {
        echo '<p>Please provide some content for the note.</p>';
    } else {
        if ($passcode === '') {
            $passcode = generateRandomPasscode(6);
        }
        if (strlen($passcode) !== 6 || !ctype_alnum($passcode)) {
            echo '<p>Passcode must be exactly 6 alphanumeric characters.</p>';
        } else {
            // Check note count limit
            $existingNotes = glob($directory . DIRECTORY_SEPARATOR . 'note_*.json') ?: [];
            if (count($existingNotes) >= $maxNotes) {
                echo '<p>The service is at capacity. Please try again later.</p>';
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
                    echo '<p>Missing encrypted payload from the browser. Please try again.</p>';
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
                    $key = getServerKey($directory);
                    $bundle = encryptContent($content, $key);
                } catch (Throwable $e) {
                    error_log('send-private-note: encryption failed: ' . $e->getMessage());
                    echo '<p>Encryption is not available. Please try again later.</p>';
                    exit;
                }

                $note = [
                    'type' => 'server',
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
                echo '<p>Failed to create the note. Please try again.</p>';
            } else {
                error_log(sprintf('send-private-note: note created id=%s type=%s ip=%s', $id, $note['type'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
                $link = basename(__FILE__) . '?note=' . urlencode($id);
                echo '<h3>Note Created</h3>';
                if ($isE2E) {
                    echo '<p>Share this link (contains the decryption key in the URL fragment; the server never sees it):</p>';
                    echo '<div id="shareLink">Generating link…</div>';
                    echo '<script>(function(){var base=' . json_encode($link) . ';var h=window.location.hash||"";var key=h.replace(/^#/,"");var full=base+(key?("#"+key):"");var a=document.createElement("a");a.href=full;a.textContent=full;a.rel="noopener";a.target="_blank";var c=document.getElementById("shareLink");c.textContent="";c.appendChild(a);})();</script>';
                } else {
                    echo '<p>Share this link (no passcode in URL):<br>';
                    echo '<a href="' . html($link) . '">' . html($link) . '</a></p>';
                }
                echo '<p>Passcode (share via a separate channel):<br><strong>' . html($passcode) . '</strong></p>';
                echo '<p>This note can be viewed once. After a successful view, it will self-destruct. It expires in 72 hours if unused.</p>';
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
        $inputPass = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';
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
            error_log(sprintf('send-private-note: bad passcode (e2e) note=%s attempt=%d ip=%s', $noteId, $data['failed_attempts'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            echo json_encode(['error' => 'bad_pass']); exit;
        }
        $payload = ['ciphertext' => $data['ciphertext'], 'iv' => $data['iv'], 'tag' => $data['tag']];
        $data['remaining_views'] = 0;
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
        flock($fp, LOCK_UN); fclose($fp);
        deleteNoteFile($path);
        error_log(sprintf('send-private-note: note consumed (e2e) id=%s ip=%s', $noteId, $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        echo json_encode(['ok' => true, 'data' => $payload]);
        exit;
    }

    // If POST view attempt
    if ($method === 'POST' && isset($_POST['action']) && $_POST['action'] === 'view') {
        if (!verifyCsrf()) {
            echo '<p>Invalid request. Please reload the page and try again.</p>';
            exit;
        }
        $inputPass = isset($_POST['passcode']) ? (string)$_POST['passcode'] : '';

        // Atomic verify + decrement under lock
        if (!is_file($path)) {
            dummyPasswordVerify($inputPass);
            echo '<p>This note does not exist or has expired.</p>';
            exit;
        }
        $fp = @fopen($path, 'r+');
        if ($fp === false) {
            dummyPasswordVerify($inputPass);
            echo '<p>This note does not exist or has expired.</p>';
            exit;
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            echo '<p>Could not lock the note. Please try again.</p>';
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
            echo '<p>This note does not exist or has expired.</p>';
            exit;
        }
        if (isset($data['expires_at']) && $now > (int)$data['expires_at']) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            echo '<p>This note has expired and is no longer available.</p>';
            exit;
        }
        if (($data['type'] ?? '') !== 'server') {
            flock($fp, LOCK_UN);
            fclose($fp);
            echo '<p>This note uses end-to-end encryption. Please refresh and use the in-browser viewer.</p>';
            exit;
        }
        if ((int)$data['remaining_views'] <= 0) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            echo '<p>This note has already been viewed and is no longer available.</p>';
            exit;
        }
        // Rate limiting: check failed attempts
        $failedAttempts = (int)($data['failed_attempts'] ?? 0);
        $lockedUntil = (int)($data['locked_until'] ?? 0);
        if ($failedAttempts >= $maxPasscodeAttempts && $now < $lockedUntil) {
            flock($fp, LOCK_UN);
            fclose($fp);
            echo '<h3>Note Locked</h3>';
            echo '<p style="color:#b00;">Too many failed attempts. Please try again later.</p>';
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
            error_log(sprintf('send-private-note: bad passcode (server) note=%s attempt=%d ip=%s', $noteId, $data['failed_attempts'], $_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            // Re-show prompt with error
            echo '<h3>Enter Passcode</h3>';
            echo '<p style="color:#b00;">Invalid passcode. Please try again.</p>';
            echo '<form method="post">';
            echo csrfField();
            echo '<input type="hidden" name="action" value="view">';
            echo '<input type="password" name="passcode" placeholder="6-character passcode" required maxlength="128"> ';
            echo '<button type="submit">View Note</button>';
            echo '</form>';
            exit;
        }

        // Valid passcode: decrypt and consume the single view
        try {
            $key = getServerKey($directory);
            $contentRaw = decryptContent($data, $key);
        } catch (Throwable $e) {
            $contentRaw = null;
        }
        if (!is_string($contentRaw)) {
            flock($fp, LOCK_UN);
            fclose($fp);
            deleteNoteFile($path);
            echo '<p>Unable to decrypt this note or it has expired.</p>';
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
        error_log(sprintf('send-private-note: note consumed (server) id=%s ip=%s', $noteId, $_SERVER['REMOTE_ADDR'] ?? 'unknown'));

        // Render the note content once
        noCacheHeaders();
        echo '<h3>Your Private Note</h3>';
        echo '<div style="white-space:pre-wrap;">' . nl2br(html($contentRaw)) . '</div>';
        echo '<p><em>This note has now been consumed and cannot be viewed again.</em></p>';
        exit;
    }

    // GET: Inspect note to decide viewer type
    $data = readNote($path);
    $now = time();
    if (!is_array($data)) { echo '<p>This note does not exist or has expired.</p>'; exit; }
    if (isset($data['expires_at']) && $now > (int)$data['expires_at']) { deleteNoteFile($path); echo '<p>This note has expired and is no longer available.</p>'; exit; }
    $type = $data['type'] ?? 'server';
    if ($type === 'e2e') {
        echo '<h3>Enter Passcode</h3>';
        echo '<p>The decryption key must be present in the URL fragment (#...). Only your browser sees it.</p>';
        echo '<div id="keyStatus" style="color:#b00;"></div>';
        echo '<input type="password" id="passcode" placeholder="6-character passcode" maxlength="128"> ';
        echo '<button id="viewBtn">Decrypt & View (consumes note)</button>';
        echo '<pre id="output" style="white-space:pre-wrap; display:none;"></pre>';
        echo '<script>
        (function(){
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
              const resp = await fetch(window.location.href, { method: "POST", headers: {"Content-Type":"application/x-www-form-urlencoded"}, body: new URLSearchParams({ action: "fetch", passcode: pass }) });
              const j = await resp.json();
              if (!j.ok) { alert(j.error || "Failed"); return; }
              const ct = b64ToBytes(j.data.ciphertext);
              const iv = b64ToBytes(j.data.iv);
              const tag = b64ToBytes(j.data.tag);
              const plaintext = await decryptGCM(key, iv, ct, tag);
              var out = document.getElementById("output");
              out.textContent = plaintext; out.style.display = "block";
              keyStatus.textContent = "";
            } catch (e) {
              alert("Decryption failed: " + e);
            }
          });
        })();
        </script>';
        exit;
    }

    // Default server-side decryption prompt
    echo '<h3>Enter Passcode</h3>';
    echo '<form method="post">';
    echo csrfField();
    echo '<input type="hidden" name="action" value="view">';
    echo '<input type="password" name="passcode" placeholder="6-character passcode" required maxlength="128"> ';
    echo '<button type="submit">View Note</button>';
    echo '</form>';
    exit;
}

// Default: show create form
$autoGeneratedPasscode = generateRandomPasscode(6);
echo '<h3>Create a Private Note</h3>';
echo '<form id="createForm" method="post" action="' . html($_SERVER['PHP_SELF']) . '">';
echo csrfField();
echo '<input type="hidden" name="action" value="create">';
echo '<label for="content">Enter the text you want to display:</label><br>';
echo '<textarea id="content" name="content" rows="6" cols="60" required></textarea><br><br>';
echo '<label for="passcode">Your 6-character passcode (auto-generated, you can change it):</label><br>';
echo '<input type="text" id="passcode" name="passcode" value="' . html($autoGeneratedPasscode) . '" maxlength="6" required> ';
echo '<div><label><input type="checkbox" id="e2e"> Encrypt in your browser (E2E)</label></div>';
echo '<button type="submit">Create Note</button>';
echo '</form>';
echo '<script>
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
?>
