<?php
// Cleanup script: deletes expired or consumed notes in private-notes/
// Usage (CLI): php cleanup_private_notes.php

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

echo "Deleted: $deleted, Kept: $kept\n";
?>

