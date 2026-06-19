<?php
/**
 * CTVLMS — Audit Logging
 */

require_once __DIR__ . '/../config/database.php';

/**
 * Write an entry to the audit_log table.
 *
 * @param string      $actionType   e.g. 'CREATE', 'UPDATE', 'DELETE', 'STATUS_CHANGE', 'LOGIN', 'LOGOUT'
 * @param string      $table        e.g. 'assets', 'vulnerabilities'
 * @param int|null    $recordID     PK of the affected record
 * @param string|null $detail       human-readable description
 */
function logAction(string $actionType, string $table, ?int $recordID = null, ?string $detail = null): void
{
    $db     = getDB();
    $userID = $_SESSION['user_id'] ?? null;

    $stmt = $db->prepare(
        'INSERT INTO audit_log (userID, actionType, tableAffected, recordID, actionDetail)
         VALUES (:uid, :action, :tbl, :rid, :detail)'
    );
    $stmt->execute([
        ':uid'    => $userID,
        ':action' => $actionType,
        ':tbl'    => $table,
        ':rid'    => $recordID,
        ':detail' => $detail,
    ]);
}
