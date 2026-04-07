<?php
// Cleanup script: deletes expired or consumed notes in private-notes/
// Usage (CLI): php cleanup_private_notes.php

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('Forbidden');
}

$directory = __DIR__ . DIRECTORY_SEPARATOR . 'private-notes';
$now = time();
$deleted = 0;
$kept = 0;

if (!is_dir($directory)) {
    fwrite(STDERR, "Directory not found: $directory\n");
    exit(1);
}

$files = glob($directory . DIRECTORY_SEPARATOR . 'note_*.json') ?: [];
foreach ($files as $path) {
    $fp = @fopen($path, 'r+');
    if ($fp === false) {
        // File may have been deleted by another process
        continue;
    }
    if (!flock($fp, LOCK_EX | LOCK_NB)) {
        // File is locked by another process, skip it
        fclose($fp);
        $kept++;
        continue;
    }
    rewind($fp);
    $raw = stream_get_contents($fp);
    $delete = false;
    if ($raw === false || $raw === '') {
        $delete = true;
    } else {
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $delete = true;
        } else {
            $expires = isset($data['expires_at']) ? (int)$data['expires_at'] : null;
            $remaining = isset($data['remaining_views']) ? (int)$data['remaining_views'] : null;
            if ($remaining !== null && $remaining <= 0) {
                $delete = true;
            }
            if ($expires !== null && $now > $expires) {
                $delete = true;
            }
        }
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    if ($delete) {
        @unlink($path);
        $deleted++;
    } else {
        $kept++;
    }
}

echo "Notes — Deleted: $deleted, Kept: $kept\n";

// Prune stale keys from the keyring.
// Keys older than TTL + rotation interval + buffer can never be needed again.
$ttlSeconds = 72 * 3600;
$keyRotationSeconds = 86400;
$maxKeyAge = $ttlSeconds + $keyRotationSeconds + 3600; // TTL + rotation + 1hr buffer

$keyringPath = $directory . DIRECTORY_SEPARATOR . '.keyring';
if (is_file($keyringPath)) {
    $fp = @fopen($keyringPath, 'r+');
    if ($fp !== false && flock($fp, LOCK_EX | LOCK_NB)) {
        rewind($fp);
        $raw = stream_get_contents($fp);
        $ring = ($raw !== '' && $raw !== false) ? json_decode($raw, true) : [];
        if (is_array($ring) && count($ring) > 1) {
            $kept_keys = [];
            $pruned_keys = 0;
            foreach ($ring as $i => $entry) {
                // Always keep the last entry (active key)
                if ($i === count($ring) - 1) {
                    $kept_keys[] = $entry;
                } elseif (($now - (int)($entry['created_at'] ?? 0)) < $maxKeyAge) {
                    $kept_keys[] = $entry;
                } else {
                    $pruned_keys++;
                }
            }
            if ($pruned_keys > 0) {
                $json = json_encode($kept_keys);
                ftruncate($fp, 0); rewind($fp); fwrite($fp, $json); fflush($fp);
            }
            echo "Keys — Pruned: $pruned_keys, Kept: " . count($kept_keys) . "\n";
        } else {
            echo "Keys — Pruned: 0, Kept: " . count($ring) . "\n";
        }
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

