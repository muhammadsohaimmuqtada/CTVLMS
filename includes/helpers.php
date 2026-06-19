<?php
/**
 * CTVLMS — Helper Functions
 */

/* ------------------------------------------------------------------ *
 * Output escaping                                                      *
 * ------------------------------------------------------------------ */

/**
 * Escape a string for safe HTML output.
 */
function e(?string $str): string
{
    return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8');
}

/* ------------------------------------------------------------------ *
 * Flash Messages                                                       *
 * ------------------------------------------------------------------ */

function flash(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function getFlash(): array
{
    $msgs = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $msgs;
}

function renderFlash(): string
{
    $html = '';
    foreach (getFlash() as $f) {
        $t = e($f['type']);
        $m = e($f['message']);
        $html .= "<div class=\"alert alert-{$t} alert-dismissible fade show\" role=\"alert\">
                     {$m}
                     <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\"></button>
                   </div>";
    }
    return $html;
}

/* ------------------------------------------------------------------ *
 * Severity / Status Badges                                             *
 * ------------------------------------------------------------------ */

function severityBadge(?string $level): string
{
    $map = [
        'Critical' => 'badge-critical',
        'High'     => 'badge-high',
        'Medium'   => 'badge-medium',
        'Low'      => 'badge-low',
    ];
    $cls = $map[$level] ?? 'bg-secondary';
    return '<span class="badge ' . $cls . '">' . e($level) . '</span>';
}

function statusBadge(?string $status): string
{
    $map = [
        // Vulnerability lifecycle
        'Discovered'               => 'bg-info',
        'Triaged'                  => 'bg-primary',
        'Confirmed'                => 'bg-warning text-dark',
        'Remediation_In_Progress'  => 'bg-orange',
        'Remediated'               => 'bg-success',
        'Verified_Closed'          => 'bg-success-dark',
        'Risk_Accepted'            => 'bg-secondary',
        // Incident
        'Open'          => 'bg-danger',
        'Investigating' => 'bg-warning text-dark',
        'Contained'     => 'bg-info',
        'Eradicated'    => 'bg-primary',
        'Recovered'     => 'bg-success',
        'Closed'        => 'bg-success-dark',
        // Engagement
        'Planned'     => 'bg-secondary',
        'In_Progress' => 'bg-primary',
        'Completed'   => 'bg-success',
        'Cancelled'   => 'bg-danger',
    ];
    $cls = $map[$status] ?? 'bg-secondary';
    $label = str_replace('_', ' ', $status ?? '');
    return '<span class="badge ' . $cls . '">' . e($label) . '</span>';
}

function criticalityBadge(?string $level): string
{
    return severityBadge($level); // same color scheme
}

/* ------------------------------------------------------------------ *
 * Pagination                                                           *
 * ------------------------------------------------------------------ */

/**
 * Generic paginator. Returns ['rows' => [...], 'total' => int, 'pages' => int].
 */
function paginate(PDO $db, string $countSql, string $dataSql, array $params, int $page = 1, int $perPage = 15): array
{
    // Count total
    $cs = $db->prepare($countSql);
    $cs->execute($params);
    $total = (int)$cs->fetchColumn();

    $pages  = max(1, (int)ceil($total / $perPage));
    $page   = max(1, min($page, $pages));
    $offset = ($page - 1) * $perPage;

    // Fetch page
    $ds = $db->prepare($dataSql . " LIMIT :lim OFFSET :off");
    foreach ($params as $k => $v) {
        $ds->bindValue($k, $v);
    }
    $ds->bindValue(':lim', $perPage, PDO::PARAM_INT);
    $ds->bindValue(':off', $offset,  PDO::PARAM_INT);
    $ds->execute();

    return [
        'rows'    => $ds->fetchAll(),
        'total'   => $total,
        'pages'   => $pages,
        'current' => $page,
    ];
}

/**
 * Render pagination links.
 */
function paginationLinks(int $current, int $totalPages, string $baseUrl): string
{
    if ($totalPages <= 1) return '';

    $html = '<nav><ul class="pagination pagination-sm justify-content-center">';

    // Previous
    $prev = max(1, $current - 1);
    $html .= '<li class="page-item ' . ($current === 1 ? 'disabled' : '') . '">
                <a class="page-link" href="' . e($baseUrl . '&pg=' . $prev) . '">&laquo;</a></li>';

    // Page numbers
    for ($i = 1; $i <= $totalPages; $i++) {
        $active = $i === $current ? 'active' : '';
        $html .= '<li class="page-item ' . $active . '">
                    <a class="page-link" href="' . e($baseUrl . '&pg=' . $i) . '">' . $i . '</a></li>';
    }

    // Next
    $next = min($totalPages, $current + 1);
    $html .= '<li class="page-item ' . ($current === $totalPages ? 'disabled' : '') . '">
                <a class="page-link" href="' . e($baseUrl . '&pg=' . $next) . '">&raquo;</a></li>';

    $html .= '</ul></nav>';
    return $html;
}

/* ------------------------------------------------------------------ *
 * Misc                                                                 *
 * ------------------------------------------------------------------ */

/**
 * Redirect helper.
 */
function redirect(string $url): void
{
    header('Location: ' . $url);
    exit;
}

/**
 * Return a formatted role label.
 */
function roleLabel(string $role): string
{
    $map = [
        'Admin'        => '<span class="badge bg-danger">Admin</span>',
        'SOC_Analyst'  => '<span class="badge bg-info">SOC Analyst</span>',
        'Red_Teamer'   => '<span class="badge bg-warning text-dark">Red Teamer</span>',
        'Vuln_Manager' => '<span class="badge bg-primary">Vuln Manager</span>',
        'Viewer'       => '<span class="badge bg-secondary">Viewer</span>',
    ];
    return $map[$role] ?? '<span class="badge bg-secondary">' . e($role) . '</span>';
}
