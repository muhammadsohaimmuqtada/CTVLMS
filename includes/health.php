<?php
/** Minimal readiness status. Never expose asset, CVE, credential, or exception details. */

function ctvlmsReadiness(PDO $db): array
{
    try {
        $value=$db->query('SELECT 1')->fetchColumn();
        return ['status'=>(int)$value===1?'ok':'unavailable'];
    } catch (Throwable) {
        return ['status'=>'unavailable'];
    }
}

function emitCtvLmsHealth(PDO $db): never
{
    $health=ctvlmsReadiness($db);
    $ok=$health['status']==='ok';
    http_response_code($ok?200:503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($health,JSON_UNESCAPED_SLASHES).PHP_EOL;
    exit;
}
